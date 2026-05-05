# ============================================================
# llm_client.py
# 用途：MiniMax LLM客户端封装（GABRIEL风格基础设施）
#       - MiniMax OpenAI兼容接口（base_url: api.minimaxi.com）
#       - 批处理 + 断点续传 + 指数退避重试
#       - JSON输出解析与验证
# ============================================================

import os
import json
import time
import re
import math
import pathlib
import logging
from typing import Any

import pandas as pd
from openai import OpenAI, APIError, RateLimitError, APITimeoutError

# --- 配置 ---
MINIMAX_BASE_URL = "https://api.minimaxi.com/v1"
DEFAULT_MODEL = "MiniMax-M2.7-highspeed"
CHECKPOINT_DIR = pathlib.Path("data/v2_checkpoints")
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0   # 秒，指数退避起始值

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _get_client() -> OpenAI:
    """创建并返回配置好的MiniMax客户端。"""
    api_key = os.environ.get("MINIMAX_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "未找到MINIMAX_API_KEY环境变量。\n"
            "请运行：export MINIMAX_API_KEY='your_key_here'"
        )
    return OpenAI(api_key=api_key, base_url=MINIMAX_BASE_URL)


def _call_llm(client: OpenAI, messages: list[dict], model: str, temperature: float = 0.1) -> str:
    """调用LLM，带指数退避重试。返回原始文本响应。"""
    for attempt in range(MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except (RateLimitError, APITimeoutError) as e:
            delay = RETRY_BASE_DELAY * (2 ** attempt)
            logger.warning(f"API限速/超时，{delay:.0f}秒后重试（第{attempt+1}次）：{e}")
            time.sleep(delay)
        except APIError as e:
            logger.error(f"API错误（第{attempt+1}次）：{e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BASE_DELAY)
    raise RuntimeError(f"达到最大重试次数({MAX_RETRIES})，API调用失败")


def _parse_json_from_response(raw: str) -> Any:
    """从LLM响应中提取JSON。支持markdown代码块包裹。"""
    # 尝试提取 ```json ... ``` 块
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if match:
        raw = match.group(1).strip()

    # 直接尝试解析
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # 尝试找到最外层的 [ ] 或 { }
        for left, right in [("[", "]"), ("{", "}")]:
            start = raw.find(left)
            end = raw.rfind(right)
            if start != -1 and end != -1:
                try:
                    return json.loads(raw[start:end+1])
                except json.JSONDecodeError:
                    continue
    raise ValueError(f"无法从响应中解析JSON：{raw[:200]}")


def _checkpoint_path(task_name: str, batch_idx: int) -> pathlib.Path:
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    return CHECKPOINT_DIR / f"{task_name}_batch{batch_idx:05d}.jsonl"


def _load_checkpoint(task_name: str, total_batches: int) -> tuple[int, list[dict]]:
    """从断点续传检查点加载已完成结果。返回(下一批索引, 已有结果列表)。"""
    results = []
    next_batch = 0
    for i in range(total_batches):
        p = _checkpoint_path(task_name, i)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        results.append(json.loads(line))
            next_batch = i + 1
        else:
            break
    if next_batch > 0:
        logger.info(f"[{task_name}] 断点续传：从第{next_batch}批继续（已完成{next_batch}批，{len(results)}条记录）")
    return next_batch, results


def _save_checkpoint(task_name: str, batch_idx: int, batch_results: list[dict]):
    """保存单批结果到检查点文件。"""
    p = _checkpoint_path(task_name, batch_idx)
    with open(p, "w", encoding="utf-8") as f:
        for record in batch_results:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def batch_extract(
    df: pd.DataFrame,
    id_column: str,
    text_column: str,
    task_name: str,
    system_prompt: str,
    user_prompt_template: str,
    output_field: str,
    batch_size: int = 20,
    model: str = DEFAULT_MODEL,
    reset: bool = False,
    text_truncate: int = 400,
) -> pd.DataFrame:
    """
    对DataFrame中每条记录调用LLM提取信息（如软技能、工具列表）。

    参数：
        df: 输入数据
        id_column: 记录唯一ID列名
        text_column: 待分析文本列名（职位描述）
        task_name: 任务名称，用于检查点文件命名
        system_prompt: 系统提示词
        user_prompt_template: 用户提示词模板，含{texts}占位符
        output_field: 解析后结果列名
        batch_size: 每批处理条数
        model: 使用的模型名称
        reset: True时清除已有检查点重新运行

    返回：
        DataFrame，含 id_column 和 output_field 两列
    """
    if reset:
        # 清除已有检查点
        for p in CHECKPOINT_DIR.glob(f"{task_name}_batch*.jsonl"):
            p.unlink()

    client = _get_client()
    records = df[[id_column, text_column]].to_dict("records")
    n = len(records)
    total_batches = math.ceil(n / batch_size)

    start_batch, all_results = _load_checkpoint(task_name, total_batches)

    logger.info(f"[{task_name}] 开始批量提取：共{n}条记录，{total_batches}批，从第{start_batch}批开始")

    for batch_idx in range(start_batch, total_batches):
        batch = records[batch_idx * batch_size: (batch_idx + 1) * batch_size]

        # 构建本批次的用户提示
        texts_block = "\n".join(
            [f'[{r[id_column]}] {str(r[text_column])[:text_truncate]}' for r in batch]
        )
        user_prompt = user_prompt_template.format(texts=texts_block, count=len(batch))

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            raw = _call_llm(client, messages, model)
            parsed = _parse_json_from_response(raw)

            # 标准化：确保输出是列表 [{id: ..., output_field: ...}, ...]
            if isinstance(parsed, list):
                batch_results = []
                for item in parsed:
                    if isinstance(item, dict):
                        batch_results.append({
                            id_column: item.get("id", item.get(id_column)),
                            output_field: item.get(output_field, item.get("result", []))
                        })
            elif isinstance(parsed, dict):
                # 可能是 {id: result} 字典形式
                batch_results = [
                    {id_column: k, output_field: v}
                    for k, v in parsed.items()
                ]
            else:
                logger.warning(f"第{batch_idx}批返回格式异常：{type(parsed)}")
                batch_results = [{id_column: r[id_column], output_field: []} for r in batch]

        except (ValueError, RuntimeError) as e:
            logger.error(f"第{batch_idx}批处理失败：{e}，用空结果填充")
            batch_results = [{id_column: r[id_column], output_field: []} for r in batch]

        all_results.extend(batch_results)
        _save_checkpoint(task_name, batch_idx, batch_results)

        if (batch_idx + 1) % 10 == 0 or (batch_idx + 1) == total_batches:
            logger.info(f"[{task_name}] 进度：{batch_idx+1}/{total_batches}批 ({(batch_idx+1)/total_batches:.1%})")

    return pd.DataFrame(all_results)


def batch_rate(
    df: pd.DataFrame,
    id_column: str,
    text_column: str,
    task_name: str,
    attributes: dict[str, str],
    batch_size: int = 10,
    model: str = DEFAULT_MODEL,
    reset: bool = False,
    text_truncate: int = 500,
) -> pd.DataFrame:
    """
    对DataFrame中每条记录评分多个属性（0-100）。

    参数：
        attributes: {属性名: 属性说明} 字典

    返回：
        DataFrame，含 id_column 和每个属性的评分列
    """
    if reset:
        for p in CHECKPOINT_DIR.glob(f"{task_name}_batch*.jsonl"):
            p.unlink()

    attr_desc = "\n".join([f"- {k}：{v}" for k, v in attributes.items()])
    attr_keys = list(attributes.keys())

    system_prompt = (
        "你是一位专业的人力资源分析师，擅长分析招聘职位描述。"
        "请严格按照要求输出JSON格式，不要添加任何额外解释。"
    )

    example_obj = '{{"id": "记录ID", ' + ", ".join([f'"{k}": 评分' for k in attr_keys]) + "}}"
    user_prompt_template = (
        f"对以下{{count}}条职位描述，分别评分以下{len(attr_keys)}个维度（0-100分整数）：\n\n"
        f"{attr_desc}\n\n"
        "输出格式（JSON数组，每条记录一个对象）：\n"
        f"[{example_obj}, ...]\n\n"
        "职位描述：\n{texts}"
    )

    client = _get_client()
    records = df[[id_column, text_column]].to_dict("records")
    n = len(records)
    total_batches = math.ceil(n / batch_size)

    start_batch, all_results = _load_checkpoint(task_name, total_batches)
    logger.info(f"[{task_name}] 开始批量评分：共{n}条记录，{total_batches}批，从第{start_batch}批开始")

    for batch_idx in range(start_batch, total_batches):
        batch = records[batch_idx * batch_size: (batch_idx + 1) * batch_size]

        texts_block = "\n".join(
            [f'[{r[id_column]}] {str(r[text_column])[:text_truncate]}' for r in batch]
        )
        user_prompt = user_prompt_template.format(texts=texts_block, count=len(batch))

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            raw = _call_llm(client, messages, model)
            parsed = _parse_json_from_response(raw)

            batch_results = []
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        record = {id_column: item.get("id", item.get(id_column))}
                        for k in attr_keys:
                            val = item.get(k)
                            try:
                                record[k] = max(0, min(100, int(val))) if val is not None else None
                            except (TypeError, ValueError):
                                record[k] = None
                        batch_results.append(record)
            else:
                raise ValueError(f"期望列表但得到：{type(parsed)}")

        except (ValueError, RuntimeError) as e:
            logger.error(f"第{batch_idx}批评分失败：{e}，用None填充")
            batch_results = [{id_column: r[id_column], **{k: None for k in attr_keys}} for r in batch]

        all_results.extend(batch_results)
        _save_checkpoint(task_name, batch_idx, batch_results)

        if (batch_idx + 1) % 10 == 0 or (batch_idx + 1) == total_batches:
            logger.info(f"[{task_name}] 进度：{batch_idx+1}/{total_batches}批 ({(batch_idx+1)/total_batches:.1%})")

    return pd.DataFrame(all_results)


def test_connection(n_samples: int = 5) -> bool:
    """
    用少量样本测试API连接和输出格式。
    返回True表示测试通过。
    """
    import sys
    sys.path.insert(0, ".")
    from scripts._common import load_filtered_data

    print("=== MiniMax API连接测试 ===")
    client = _get_client()
    print(f"客户端创建成功，base_url: {MINIMAX_BASE_URL}")

    # 加载测试样本
    df, _ = load_filtered_data()
    sample = df[["招聘岗位", "职位描述"]].dropna().head(n_samples).reset_index(drop=True)
    sample["test_id"] = [f"TEST_{i:03d}" for i in range(len(sample))]

    # 测试提取功能
    print(f"\n测试批量提取（{n_samples}条样本）...")
    system_prompt = (
        "你是招聘数据分析师。请从职位描述中提取软技能要求。"
        "只返回JSON，不要其他文字。"
    )
    user_prompt_template = (
        "从以下职位描述中提取软技能（如沟通、团队协作、执行力等），"
        "每条记录输出一个JSON对象。\n\n"
        "输出格式：\n"
        '[{{"id": "记录ID", "soft_skills": ["技能1", "技能2"]}}, ...]\n\n'
        "职位描述：\n{texts}"
    )

    result_df = batch_extract(
        df=sample,
        id_column="test_id",
        text_column="职位描述",
        task_name="test_extract",
        system_prompt=system_prompt,
        user_prompt_template=user_prompt_template,
        output_field="soft_skills",
        batch_size=n_samples,
        reset=True,
    )

    print("\n提取结果：")
    for _, row in result_df.iterrows():
        print(f"  {row['test_id']}: {row.get('soft_skills', [])}")

    success_rate = result_df["soft_skills"].apply(lambda x: isinstance(x, list) and len(x) > 0).mean()
    print(f"\n成功率：{success_rate:.1%}（目标>80%）")

    # 测试评分功能
    print(f"\n测试批量评分（{n_samples}条样本）...")
    rating_df = batch_rate(
        df=sample,
        id_column="test_id",
        text_column="职位描述",
        task_name="test_rate",
        attributes={
            "数字化程度": "该岗位涉及数字化技术、信息系统的程度",
            "技术复杂度": "该岗位要求的技术技能的复杂程度",
        },
        batch_size=n_samples,
        reset=True,
    )

    print("\n评分结果：")
    print(rating_df.to_string())

    print("\n=== 测试完成 ===")
    return success_rate >= 0.8


if __name__ == "__main__":
    test_connection()
