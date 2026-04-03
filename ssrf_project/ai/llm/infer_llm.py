import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from peft import PeftModel

# Load base model
model_name = "microsoft/Phi-3-mini-4k-instruct"
lora_path = "ssrf_llm_lora"

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)

print("Loading base model on accelerate (GPU auto)…")
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,           # Works on 4080
    device_map="auto",                   # <-- accelerate decides
)

print("Applying LoRA...")
model = PeftModel.from_pretrained(model, lora_path)
model.eval()

print("\nPreparing pipeline…")
# ❗ REMOVE device=device because accelerate already handles it
pipe = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    max_new_tokens=256,
)

print("\n🔥 Model ready. Running inference...\n")

prompt = """Analyze this endpoint for SSRF:
method=GET
path=/image
user_supplied_url=1
contains_ip_literal=1
contains_internal_keyword=1
"""

result = pipe(prompt)[0]["generated_text"]

print("\n=== MODEL OUTPUT ===\n")
print(result)
print("\n====================\n")
