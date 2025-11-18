#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Process answer.txt lists (separated by <END>) for multiple targets,
using PII from an online dataset to build zxcvbn user_inputs.

For each target:
  • Merge candidates from ALL answer files
  • Deduplicate
  • Score with zxcvbn (guesses)
  • Keep top 10,000 most likely (smallest guesses)

Write answer_final.txt in the same segmented format (<END> separators).

Usage:
    python process.py ./在线数据集.txt ./answers

Dependencies:
    pip install zxcvbn tqdm

Notes:
    - Only run this on datasets you have the right to analyze.
    - The dataset line format is tolerant, e.g.:
        email:foo@bar.com    name:JOHN|PAUL|SMITH    account:johnsmith    phone:12345678    birth:19840603
      Fields may be empty.
"""

import argparse
import sys
import re
from pathlib import Path
from typing import List, Dict, Tuple
from multiprocessing import Pool, cpu_count

try:
    from zxcvbn import zxcvbn
except Exception as e:
    print("[!] Missing dependency: zxcvbn. Please run: pip install zxcvbn", file=sys.stderr)
    sys.exit(1)

try:
    from tqdm import tqdm
except Exception:
    tqdm = None  # Fallback to plain prints if tqdm is unavailable


def parse_dataset_line(line: str) -> Dict[str, str]:
    """
    Parse one dataset line like:
      email:foo@bar.com\tname:JOHN|PAUL|SMITH\taccount:johnsmith\tphone:12345678\tbirth:19840603
    Returns a dict with keys: email, name, account, phone, birth (when present).
    """
    out: Dict[str, str] = {}
    # Split by tabs or multiple spaces to be tolerant
    for part in re.split(r'\t+|\s{2,}', line.strip()):
        if not part:
            continue
        if ':' in part:
            k, v = part.split(':', 1)
            out[k.strip().lower()] = v.strip()
    return out


MONTHS = {
    'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4, 'MAY': 5, 'JUN': 6,
    'JUL': 7, 'AUG': 8, 'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12
}


def birth_tokens(birth: str) -> List[str]:
    """Extract useful date fragments from a variety of birth formats."""
    res: List[str] = []
    b = (birth or "").strip()
    if not b:
        return res

    # Case 1: pure digits, e.g., 19890627
    m = re.fullmatch(r'(\d{8})', b)
    if m:
        s = m.group(1)
        yyyy, mm, dd = s[:4], s[4:6], s[6:8]
        yy = yyyy[-2:]
        res += [s, yyyy, yy, mm, dd, mm + dd, yyyy + mm, dd + mm + yyyy]
        return res

    # Case 2: dd-MON-yy or dd-MON-yyyy (e.g., 06-JAN-09)
    m = re.fullmatch(r'(\d{1,2})-([A-Za-z]{3})-(\d{2,4})', b)
    if m:
        d = int(m.group(1))
        mon_txt = m.group(2).upper()
        y_str = m.group(3)
        mon = MONTHS.get(mon_txt)
        if mon:
            if len(y_str) == 2:
                y = int(y_str)
                y = 1900 + y if y >= 50 else 2000 + y
            else:
                y = int(y_str)
            mm = f'{mon:02d}'
            dd = f'{d:02d}'
            yyyy = str(y)
            yy = yyyy[-2:]
            res += [yyyy, yy, mm, dd, mm + dd, yyyy + mm + dd, dd + mm + yyyy]

    # Fallback: collect any 2..8 digit sequences
    res += re.findall(r'\d{2,8}', b)
    return res


def tokens_from_record(fields: Dict[str, str]) -> List[str]:
    """
    Build a zxcvbn user_inputs list from a record dict.
    Includes email parts, account, phone fragments, birth fragments, and name pieces.
    """
    tokens: List[str] = []

    # email
    email = fields.get('email') or ''
    if email:
        tokens.append(email)
        if '@' in email:
            local, domain = email.split('@', 1)
            tokens += [local, domain]
            domain_base = domain.split('.')[0]
            tokens.append(domain_base)

    # account
    acc = fields.get('account') or ''
    if acc:
        tokens.append(acc)

    # phone: digits only; add last 2/3/4 as well
    phone_digits = re.sub(r'\D+', '', (fields.get('phone') or ''))
    if phone_digits:
        tokens.append(phone_digits)
        if len(phone_digits) >= 2:
            tokens.append(phone_digits[-2:])
        if len(phone_digits) >= 3:
            tokens.append(phone_digits[-3:])
        if len(phone_digits) >= 4:
            tokens.append(phone_digits[-4:])

    # birth date fragments
    tokens += birth_tokens(fields.get('birth') or '')

    # name parts: split on | . _ - space; drop common titles
    name = fields.get('name') or ''
    if name:
        raw_parts = re.split(r'[|\s._\-]+', name)
        titles = {'MR', 'MS', 'MRS', 'MISS', 'DR', 'JR', 'SR',
                  'MR.', 'MS.', 'MRS.', 'MISS.'}
        cleaned = []
        for p in raw_parts:
            p = p.strip().strip('.')
            if not p:
                continue
            up = p.upper()
            if up in titles:
                continue
            cleaned.append(p)
            tokens.extend({p, p.lower(), p.capitalize()})
        if cleaned:
            joined = ''.join(cleaned)
            tokens.extend({joined, joined.lower(), joined.capitalize()})

    # Dedup while preserving order
    seen = set()
    uniq: List[str] = []
    for t in tokens:
        t = (t or '').strip()
        if not t or t in seen:
            continue
        seen.add(t)
        uniq.append(t)

    return uniq


def read_answer_file(path: Path) -> List[List[str]]:
    """
    Read one answer.txt, return a list of segments (each segment = list of guesses).
    Segments are separated by a line that is exactly '<END>'.
    Lines may contain inline comments like 'password # note' -> we keep the part before ' #'
    """
    segments: List[List[str]] = []
    current: List[str] = []
    with path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            if s == '<END>':
                segments.append(current)
                current = []
                continue
            # Remove inline comment (space + '#') but keep '#' if part of the password
            if ' #' in s:
                s = s.split(' #', 1)[0].strip()
                if not s:
                    continue
            current.append(s)
    if current:  # trailing segment if file didn't end with <END>
        segments.append(current)
    return segments


def merge_segments_by_index(all_files_segments: List[List[List[str]]], index: int) -> List[str]:
    """Merge the segment 'index' from each file's segment list, deduped."""
    merged = set()
    for seglist in all_files_segments:
        if index < len(seglist):
            merged.update(seglist[index])
    return list(merged)


def score_one(args: Tuple[str, List[str]]) -> Tuple[str, int]:
    """Helper for parallel scoring."""
    pw, user_inputs = args
    try:
        r = zxcvbn(pw, user_inputs=user_inputs)
        return pw, int(r.get('guesses', 0))
    except Exception:
        # If zxcvbn errors (too long etc.), push to the end by giving a huge guesses value
        return pw, 10**30


def run(dataset_path: Path, answers_dir: Path, topk: int = 10000, workers: int = None) -> Path:
    # 1) Load dataset
    records: List[Dict[str, str]] = []
    with dataset_path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = parse_dataset_line(line)
            if rec:
                records.append(rec)
    print(f"[+] Loaded {len(records)} records from {dataset_path}")

    # 2) Build user_inputs for each record
    user_inputs_list: List[List[str]] = [tokens_from_record(rec) for rec in records]

    # 3) Read all answer files
    answer_files = sorted([p for p in answers_dir.glob('*.txt') if p.name != 'answer_final.txt'])
    if not answer_files:
        print(f"[!] No .txt files found under {answers_dir}", file=sys.stderr)
        sys.exit(2)
    print(f"[+] Found {len(answer_files)} answer file(s) in {answers_dir}")

    all_files_segments: List[List[List[str]]] = []
    iterator = answer_files
    if tqdm:
        iterator = tqdm(answer_files, desc="Reading answer files", unit="file")
    for p in iterator:
        all_files_segments.append(read_answer_file(p))

    # 4) Iterate targets
    N = len(records)
    out_path = answers_dir / 'answer_final.txt'
    if out_path.exists():
        out_path.unlink()

    # Decide workers
    if workers is None:
        workers = max(1, min(8, cpu_count()))

    # Create a single pool to amortize startup cost
    with Pool(processes=workers) as pool, out_path.open('w', encoding='utf-8') as out_f:
        outer = range(N)
        if tqdm:
            outer = tqdm(outer, desc="Scoring targets", unit="target")
        for i in outer:
            candidates = merge_segments_by_index(all_files_segments, i)
            # Dedup already done via set; shuffle not needed

            ui = user_inputs_list[i] if i < len(user_inputs_list) else []
            # Chunked parallel scoring for progress within target
            chunksize = max(1, len(candidates) // (workers * 4) or 1)
            inner_iter = pool.imap(score_one, ((pw, ui) for pw in candidates), chunksize=chunksize)
            scored: List[Tuple[str, int]]
            if tqdm:
                scored = list(tqdm(inner_iter, total=len(candidates), leave=False, desc=f"Target {i+1}/{N}"))
            else:
                scored = list(inner_iter)

            # Sort by guesses ascending (smaller = easier to guess)
            scored.sort(key=lambda x: x[1])
            top = [pw for pw, g in scored[:topk]]

            # Write this segment
            for pw in top:
                out_f.write(pw + "\n")
            out_f.write("<END>\n")

    print(f"[+] Done. Wrote {out_path}")
    return out_path


def main():
    parser = argparse.ArgumentParser(
        description="Merge & rank answer guesses per target using zxcvbn with PII-informed user_inputs."
    )
    parser.add_argument("dataset", type=Path, help="Path to 在线数据集.txt")
    parser.add_argument("answers_dir", type=Path, help="Path to folder containing answer*.txt files")
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"[!] Dataset not found: {args.dataset}", file=sys.stderr)
        sys.exit(2)
    if not args.answers_dir.exists() or not args.answers_dir.is_dir():
        print(f"[!] Answers directory not found or not a directory: {args.answers_dir}", file=sys.stderr)
        sys.exit(2)

    try:
        run(args.dataset, args.answers_dir)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
