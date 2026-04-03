import os
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

# ============================================
# DOCKER PATH FOR LORA
# ============================================
LORA_PATH = "/app/ai/llm/ssrf_llm_lora"
BASE_MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"

# Cache model so it's not loaded again
_model = None
_tokenizer = None


def load_model():
    global _model, _tokenizer

    if _model is not None:
        return _model, _tokenizer

    print("[AI] Loading base model:", BASE_MODEL_NAME)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto"
    )

    if os.path.exists(LORA_PATH):
        print("[AI] Loading LoRA adapter from:", LORA_PATH)
        model = PeftModel.from_pretrained(base_model, LORA_PATH)
    else:
        print("[AI] WARNING: LoRA not found. Running base model only.")
        model = base_model

    _model = model
    _tokenizer = tokenizer
    return model, tokenizer


def classify_ssrf(category, payload, risk):
    model, tokenizer = load_model()

    prompt = (
        f"Payload category: {category}\n"
        f"Payload: {payload}\n"
        f"Risk: {risk}\n"
        f"Decide if this payload indicates SSRF vulnerability. "
        f"Answer only VULNERABLE or SAFE."
    )

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    output = model.generate(**inputs, max_new_tokens=5)
    text = tokenizer.decode(output[0], skip_special_tokens=True).upper()

    if "VULNERABLE" in text:
        return "VULNERABLE"
    return "SAFE"
