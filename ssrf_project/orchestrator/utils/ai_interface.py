import os
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

LORA_PATH = "/app/ai/llm/ssrf_llm_lora"
BASE_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"

_model = None
_tokenizer = None


def load_model():
    global _model, _tokenizer

    if _model is not None:
        return _model, _tokenizer

    print("[AI] Loading base model:", BASE_MODEL_NAME)

    # FIX: Phi-3 requires trust_remote_code=True — without this it crashes
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_NAME,
        trust_remote_code=True
    )

    # FIX: use float32 explicitly on CPU to avoid half-precision errors
    dtype = torch.float16 if torch.cuda.is_available() else torch.float32

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        torch_dtype=dtype,
        device_map="auto",
        trust_remote_code=True,       # FIX: required for Phi-3
        low_cpu_mem_usage=True,       # FIX: avoids OOM on low-RAM Docker
    )

    if os.path.exists(LORA_PATH):
        print("[AI] Loading LoRA adapter from:", LORA_PATH)
        model = PeftModel.from_pretrained(base_model, LORA_PATH)
    else:
        print("[AI] WARNING: LoRA not found at", LORA_PATH, "- running base model only.")
        model = base_model

    model.eval()   # FIX: set eval mode — skips dropout, faster inference
    _model = model
    _tokenizer = tokenizer
    return model, tokenizer


def classify_ssrf(category: str, payload: str, risk: str) -> str:
    """
    Returns 'VULNERABLE' or 'SAFE'.
    """
    model, tokenizer = load_model()

    prompt = (
        f"<|user|>\n"
        f"Payload category: {category}\n"
        f"Payload: {payload}\n"
        f"Risk: {risk}\n"
        f"Is this payload an SSRF vulnerability? Answer only VULNERABLE or SAFE.\n"
        f"<|end|>\n"
        f"<|assistant|>\n"
    )

    # FIX: use Phi-3 chat format — plain prompts produce garbage outputs
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    with torch.no_grad():   # FIX: no_grad required for inference, else OOM
        output = model.generate(
            **inputs,
            max_new_tokens=10,
            do_sample=False,       # greedy — deterministic classification
            temperature=1.0,
            pad_token_id=tokenizer.eos_token_id,
        )

    # Decode only the newly generated tokens
    new_tokens = output[0][inputs["input_ids"].shape[1]:]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip().upper()

    if "VULNERABLE" in text:
        return "VULNERABLE"
    return "SAFE"