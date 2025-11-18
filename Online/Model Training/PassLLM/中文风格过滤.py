"""Merge password guess lists for each identity with heuristic filtering."""

from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


PINYIN_KEYWORDS: tuple[str, ...] = (
    "zhang",
    "wang",
    "chen",
    "liu",
    "zhao",
    "yang",
    "huang",
    "zhou",
    "zheng",
    "xiao",
    "tang",
    "song",
    "liang",
    "cai",
    "jing",
    "qing",
    "hao",
    "lin",
    "meng",
    "rui",
    "lei",
    "chao",
    "long",
    "sheng",
    "ming",
    "xuan",
    "yuan",
    "dong",
    "tong",
    "wen",
    "hua",
    "yong",
    "wei",
    "ning",
    "yuan",
    "han",
    "qian",
    "xue",
    "yue",
    "xin",
    "xiaoming",
    "xiaohong",
    "xiaoli",
    "laogong",
    "laopo",
    "zhongguo",
)

CHINESE_STYLE_PATTERNS: tuple[str, ...] = (
    "520",
    "521",
    "1314",
    "7758",
    "5211314",
    "666",
    "888",
    "nihao",
    "woaini",
    "aini",
    "china",
    "zh",
    "qq",
)


@dataclass(frozen=True)
class MergeStats:
    identities: int
    total_candidates: int
    unique_candidates: int
    filtered_chinese_style: int


def iter_password_blocks(path: Path, overflow_counter: list[int]) -> Iterator[list[str]]:
    """Yield ordered password guesses for each identity."""

    block: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if line == "<END>":
                if len(block) < 10000:
                    raise ValueError(
                        f"Too few guesses ({len(block)}) before <END> in {path}."
                    )
                if len(block) > 10000:
                    overflow_counter[0] += len(block) - 10000
                    block = block[:10000]
                yield block
                block = []
                continue
            block.append(line)

    if block:
        raise ValueError(f"Missing <END> sentinel at end of {path}.")


def is_chinese_style(password: str) -> bool:
    """Detect passwords that resemble Chinese naming or common patterns."""

    if not password.isascii():
        return True

    lower = password.lower()

    for keyword in PINYIN_KEYWORDS:
        if len(keyword) >= 4 and keyword in lower:
            return True

    for pattern in CHINESE_STYLE_PATTERNS:
        if pattern in lower:
            return True

    return False


def merge_identity_guesses(primary: list[str], secondary: list[str]) -> tuple[list[str], int, int]:
    """Merge two ordered guess lists, returning top 10k candidates."""

    combined = OrderedDict[str, None]()
    for guess in primary:
        combined.setdefault(guess, None)
    for guess in secondary:
        combined.setdefault(guess, None)

    all_unique = list(combined.keys())

    filtered = [candidate for candidate in all_unique if not is_chinese_style(candidate)]

    if len(filtered) >= 10000:
        selected = filtered[:10000]
        filtered_drop = len(all_unique) - len(filtered)
    else:
        selected = all_unique[:10000]
        filtered_drop = 0

    return selected, len(all_unique), filtered_drop


def merge_password_files(
    primary_path: Path,
    secondary_path: Path,
    identities_path: Path,
    output_path: Path,
) -> MergeStats:
    identities_data = json.loads(identities_path.read_text(encoding="utf-8"))

    primary_overflow = [0]
    secondary_overflow = [0]
    primary_blocks = iter_password_blocks(primary_path, primary_overflow)
    secondary_blocks = iter_password_blocks(secondary_path, secondary_overflow)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    identities = 0
    total_candidates = 0
    unique_candidates = 0
    filtered_chinese_style = 0

    with output_path.open("w", encoding="utf-8") as writer:
        for identities, (primary, secondary) in enumerate(
            zip(primary_blocks, secondary_blocks), start=1
        ):
            merged, unique_count, filtered_drop = merge_identity_guesses(primary, secondary)

            total_candidates += len(primary) + len(secondary)
            unique_candidates += unique_count
            filtered_chinese_style += filtered_drop

            for guess in merged:
                writer.write(f"{guess}\n")
            writer.write("<END>\n")

    if identities != len(identities_data):
        raise ValueError(
            "Identity count mismatch: "
            f"merged {identities} blocks but have {len(identities_data)} identities."
        )

    leftover_primary = next(primary_blocks, None)
    leftover_secondary = next(secondary_blocks, None)
    if leftover_primary is not None or leftover_secondary is not None:
        raise ValueError(
            "Password files contain more blocks than identities: "
            f"primary leftover block? {leftover_primary is not None}, "
            f"secondary leftover block? {leftover_secondary is not None}."
        )

    if primary_overflow[0] or secondary_overflow[0]:
        print(
            f"Trimmed overflow guesses -> primary: {primary_overflow[0]}, "
            f"secondary: {secondary_overflow[0]}"
        )

    return MergeStats(
        identities=identities,
        total_candidates=total_candidates,
        unique_candidates=unique_candidates,
        filtered_chinese_style=filtered_chinese_style,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge two password guess files per identity and keep top 10k entries.",
    )
    parser.add_argument(
        "--primary",
        type=Path,
        default=Path("/home/ubuntu/datacon/passllm/answer-6.txt"),
        help="Primary password guess file with 10000 lines plus <END> per identity.",
    )
    parser.add_argument(
        "--secondary",
        type=Path,
        default=Path("/home/ubuntu/datacon/passllm/gen/csdn_testdata_guesses.txt"),
        help="Secondary password guess file with 10000 lines plus <END> per identity.",
    )
    parser.add_argument(
        "--identities",
        type=Path,
        default=Path("/home/ubuntu/datacon/passllm/testdata_processed.json"),
        help="Identity metadata file to validate block counts.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/home/ubuntu/datacon/passllm/gen/merged_top10k.txt"),
        help="Output file path for merged guesses.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    stats = merge_password_files(
        primary_path=args.primary,
        secondary_path=args.secondary,
        identities_path=args.identities,
        output_path=args.output,
    )

    print(
        "Merged {identities} identities, {total_candidates} candidates -> "
        "{unique_candidates} unique, filtered {filtered_chinese_style} Chinese-style".format(
            identities=stats.identities,
            total_candidates=stats.total_candidates,
            unique_candidates=stats.unique_candidates,
            filtered_chinese_style=stats.filtered_chinese_style,
        )
    )


if __name__ == "__main__":
    main()
