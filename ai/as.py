import json
from openai import OpenAI
from sklearn.metrics import accuracy_score

client = OpenAI()

# Load LLM dataset
samples = []
with open("../data/processed/dataset1_llm.jsonl", "r") as f:
    for line in f:
        samples.append(json.loads(line))

# Function to query the LLM
def ask_llm(prompt):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a security log analysis model. Respond only with True or False."},
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )
    return response.choices[0].message.content.strip()

# Evaluate on first 200 samples (to save cost/time)
y_true = []
y_pred = []

for sample in samples[:200]:
    log_text = sample["input"]
    correct_answer = sample["output"]  # True/False from your pseudo-label
    
    llm_output = ask_llm(log_text)

    y_true.append(correct_answer)
    y_pred.append(llm_output)

accuracy = accuracy_score(y_true, y_pred)

print("LLM Accuracy on Dataset 1:", accuracy)
