import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

base_model_name = "microsoft/Phi-3-mini-4k-instruct"
lora_path = "ssrf_llm_lora"

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token

print("Loading base model with LoRA on GPU...")
device = "cuda" if torch.cuda.is_available() else "cpu"

model = AutoModelForCausalLM.from_pretrained(
    base_model_name,
    torch_dtype=torch.float16,
    trust_remote_code=True,
    device_map=None,
)
model = PeftModel.from_pretrained(model, lora_path)
model.to(device)
model.eval()

print(f"Using device: {device}")

def generate_response(user_prompt: str) -> str:
    full_prompt = (
        "Instruction:\n"
        "Analyze this input in the context of SSRF and web security. "
        "Explain whether it is vulnerable or safe, and why.\n\n"
        f"Input:\n{user_prompt}\n\n"
        "Response:"
    )

    inputs = tokenizer(full_prompt, return_tensors="pt").to(device)

    with torch.no_grad():
        output_ids = model.generate(
   		 **inputs,
    		max_new_tokens=256,
   	 do_sample=True,
   	 temperature=0.4,
    	top_p=0.9,
   	 use_cache=False   # <<< CRUCIAL FIX
	)


    text = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    if "Response:" in text:
        text = text.split("Response:", 1)[1].strip()
    return text

print("\n🔥 SSRF LLM ready. Type your questions. Type 'exit' to quit.\n")

while True:
    try:
        user_input = input("You> ").strip()
        if user_input.lower() in {"exit", "quit"}:
            print("Bye!")
            break
        if not user_input:
            continue

        reply = generate_response(user_input)
        print("\nAI> " + reply + "\n")

    except KeyboardInterrupt:
        print("\n[Interrupted] Bye!")
        break
