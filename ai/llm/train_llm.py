import torch
torch.multiprocessing.set_start_method("spawn", force=True)

from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
)
from peft import LoraConfig, get_peft_model

# --------------------------
# Load dataset
# --------------------------
print("Loading dataset...")
dataset = load_dataset("json", data_files="ssrf_llm_dataset.jsonl")

model_name = "microsoft/Phi-3-mini-4k-instruct"
tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)

def format_example(example):
    # same style used during training/inference
    prompt = (
        f"Instruction:\n{example['instruction']}\n\n"
        f"Input:\n{example['input']}\n\n"
        "Response:"
    )
    prompt_ids = tokenizer(prompt, add_special_tokens=False).input_ids
    output_ids = tokenizer(example["output"], add_special_tokens=False).input_ids

    input_ids = prompt_ids + output_ids
    labels = [-100] * len(prompt_ids) + output_ids

    return {"input_ids": input_ids, "labels": labels}

print("Formatting dataset...")
dataset = dataset.map(format_example)

# --------------------------
# Load base model on GPU
# --------------------------
device = "cuda" if torch.cuda.is_available() else "cpu"
print("Using device:", device)

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,
    trust_remote_code=True,
    use_cache=False,
    attn_implementation="eager",
    device_map=None,
)
model.to(device)

# --------------------------
# LoRA configuration
# --------------------------
lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    lora_dropout=0.05,
    target_modules=[
        "q_proj",
        "k_proj",
        "v_proj",
        "o_proj",
        "gate_proj",
        "up_proj",
        "down_proj",
    ],
)

model = get_peft_model(model, lora_config)
model.to(device)

# --------------------------
# Data collator
# --------------------------
data_collator = DataCollatorForSeq2Seq(
    tokenizer=tokenizer,
    model=model,
    padding=True,
)

# --------------------------
# Training arguments
# --------------------------
args = TrainingArguments(
    output_dir="ssrf_llm_lora",
    per_device_train_batch_size=1,
    gradient_accumulation_steps=2,
    warmup_steps=10,
    max_steps=200,           # more steps for larger dataset
    learning_rate=2e-4,
    fp16=True,
    bf16=False,
    logging_steps=5,
    save_strategy="steps",
    save_steps=100,
    dataloader_num_workers=0,
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=dataset["train"],
    data_collator=data_collator,
)

print("Starting training...")
trainer.train()

print("Saving LoRA adapter and tokenizer...")
model.save_pretrained("ssrf_llm_lora")
tokenizer.save_pretrained("ssrf_llm_lora")

print("Done. LoRA weights stored in ssrf_llm_lora/")
