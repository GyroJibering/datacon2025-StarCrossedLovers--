import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from tqdm import tqdm

from src.utils.tokenize import get_alpha_vocab, process_test_targeted
from src.search.search import dynamic_beam_search, post_process_sequences, random_sample


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate password guesses for targeted identities."
    )
    parser.add_argument(
        "--input-json",
        type=Path,
        default=Path("data/testdata_processed.json"),
        help="Path to processed identity JSON.",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=Path("gen/testdata_guesses.txt"),
        help="Where to write generated guesses.",
    )
    parser.add_argument(
        "--base-model-path",
        type=Path,
        default=Path(".model/Qwen2.5-0.5B-Instruct"),
        help="Base model directory.",
    )
    parser.add_argument(
        "--lora-path",
        type=Path,
        default=Path("checkpoints/126_csdn_disQwen0.5B"),
        help="LoRA checkpoint to merge.",
    )
    parser.add_argument(
        "--prompt-template-id",
        type=int,
        default=0,
        help="Prompt template id for targeted guessing.",
    )
    parser.add_argument(
        "--num-guesses",
        type=int,
        default=10_000,
        help="Number of guesses to output per identity.",
    )
    parser.add_argument(
        "--beam-guesses",
        type=int,
        default=4_000,
        help="Target number of guesses from dynamic beam search.",
    )
    parser.add_argument(
        "--beam-width",
        type=int,
        default=1024,
        help="Beam width used at each decoding step.",
    )
    parser.add_argument(
        "--beam-steps",
        type=int,
        default=16,
        help="Maximum generated length (in tokens) for beam search.",
    )
    parser.add_argument(
        "--beam-batch-size",
        type=int,
        default=64,
        help="Micro batch size for beam search forward passes.",
    )
    parser.add_argument(
        "--eos-threshold",
        type=float,
        default=1e-4,
        help="EOS probability threshold for beam search.",
    )
    parser.add_argument(
        "--sample-batch-size",
        type=int,
        default=128,
        help="Batch size for random sampling.",
    )
    parser.add_argument(
        "--sample-chunk",
        type=int,
        default=2_000,
        help="How many samples to draw per random sampling round.",
    )
    parser.add_argument(
        "--sample-max-length",
        type=int,
        default=18,
        help="Maximum number of new tokens for random sampling.",
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Device to place model on. Defaults to CUDA if available.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output file if it already exists.",
    )
    parser.add_argument(
        "--max-identities",
        type=int,
        default=None,
        help="Optionally limit the number of identities processed (for debugging).",
    )
    return parser.parse_args()


def load_identities(path: Path) -> List[Dict]:
    with path.open() as fh:
        return json.load(fh)


def prepare_output_path(path: Path, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists. Use --overwrite to replace it.")


def load_model_and_tokenizer(
    base_model_path: Path,
    lora_path: Path | None,
    device: str | None = None,
) -> Tuple[AutoModelForCausalLM, AutoTokenizer, Dict[str, int]]:
    resolved_device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    if resolved_device != "cpu" and resolved_device != "cuda":
        resolved_device = resolved_device.strip()
    torch_dtype = torch.float16 if resolved_device.startswith("cuda") else torch.float32

    model = AutoModelForCausalLM.from_pretrained(
        base_model_path,
        torch_dtype=torch_dtype,
        trust_remote_code=True,
        device_map="auto" if resolved_device.startswith("cuda") else None,
    )

    if not resolved_device.startswith("cuda"):
        model.to(resolved_device)

    if lora_path and lora_path.exists():
        model = PeftModel.from_pretrained(
            model,
            model_id=str(lora_path),
            is_trainable=False,
        ).merge_and_unload()
        model.to(resolved_device)

    tokenizer = AutoTokenizer.from_pretrained(
        base_model_path,
        trust_remote_code=True,
    )
    tokenizer.pad_token_id = tokenizer.eos_token_id

    vocab = get_alpha_vocab(tokenizer)
    model.eval()
    return model, tokenizer, vocab


def decode_sequences(
    sequences: Iterable[Tuple[float, str]],
    seen: set[str],
    limit: int,
) -> List[str]:
    guesses: List[str] = []
    for _, seq in sequences:
        clean = seq.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        guesses.append(clean)
        if len(guesses) >= limit:
            break
    return guesses


def generate_beam_guesses(
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    vocab_values: List[int],
    prompt_tensor: torch.Tensor,
    beam_width: int,
    beam_steps: int,
    batch_size: int,
    eos_threshold: float,
    limit: int,
) -> List[str]:
    if limit <= 0:
        return []
    beam_width_list = [beam_width] * beam_steps
    beam_sequences = dynamic_beam_search(
        model=model,
        input_ids=prompt_tensor,
        batch_size=batch_size,
        beam_width_list=beam_width_list,
        vocab=vocab_values,
        eos_threshold=eos_threshold,
        search_width_list=beam_width_list,
        sorted=True,
    )
    processed = post_process_sequences(
        finished_sequences=beam_sequences,
        tokenizer=tokenizer,
        sort_by_score=True,
        verbose=False,
    )
    return decode_sequences(processed, seen=set(), limit=limit)


def generate_sampling_guesses(
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    vocab: Dict[str, int],
    prompt_tensor: torch.Tensor,
    batch_size: int,
    max_length: int,
    chunk_size: int,
    limit: int,
    already_seen: set[str],
) -> List[str]:
    guesses: List[str] = []
    while len(guesses) < limit:
        request_size = min(chunk_size, (limit - len(guesses)) * 2)
        sampling_results = random_sample(
            model=model,
            tokenizer=tokenizer,
            vocab=vocab,
            batch_size=batch_size,
            max_length=max_length,
            sample_size=request_size,
            prompt_ids=prompt_tensor,
            output_file=None,
        )
        decoded = decode_sequences(sampling_results, seen=already_seen, limit=limit - len(guesses))
        guesses.extend(decoded)
        if not decoded:
            break
    return guesses


def main() -> None:
    args = parse_args()
    identities = load_identities(args.input_json)
    prepare_output_path(args.output_path, args.overwrite)

    model, tokenizer, vocab = load_model_and_tokenizer(
        base_model_path=args.base_model_path,
        lora_path=args.lora_path,
        device=args.device,
    )
    vocab_values = list(vocab.values())

    if args.max_identities is not None:
        identities = identities[: args.max_identities]

    total_required = args.num_guesses
    beam_target = min(args.beam_guesses, total_required)
    sample_target = total_required - beam_target

    with args.output_path.open("w") as writer:
        for item in tqdm(identities, desc="Generating identities"):
            example = {
                "Knowledge": item.get("Knowledge", {}),
                "password": item.get("password", ""),
            }
            encoded = process_test_targeted(
                example=example,
                tokenizer=tokenizer,
                prompt_id=args.prompt_template_id,
            )
            prompt_tensor = encoded["input_ids_no_response"]
            seen: set[str] = set()

            beam_guesses = generate_beam_guesses(
                model=model,
                tokenizer=tokenizer,
                vocab_values=vocab_values,
                prompt_tensor=prompt_tensor,
                beam_width=args.beam_width,
                beam_steps=args.beam_steps,
                batch_size=args.beam_batch_size,
                eos_threshold=args.eos_threshold,
                limit=beam_target,
            )
            for guess in beam_guesses:
                writer.write(f"{guess}\n")
            seen.update(beam_guesses)

            if sample_target > 0:
                sample_guesses = generate_sampling_guesses(
                    model=model,
                    tokenizer=tokenizer,
                    vocab=vocab,
                    prompt_tensor=prompt_tensor,
                    batch_size=args.sample_batch_size,
                    max_length=args.sample_max_length,
                    chunk_size=args.sample_chunk,
                    limit=sample_target,
                    already_seen=seen,
                )
                for guess in sample_guesses:
                    writer.write(f"{guess}\n")
                seen.update(sample_guesses)

            if len(seen) < total_required:
                # Pad with empty placeholders if generation finishes early.
                for _ in range(total_required - len(seen)):
                    writer.write("\n")
            writer.write("<END>\n")


if __name__ == "__main__":
    main()

