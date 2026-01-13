from phi_pii_deidentifier import deidentify

text = "On January 5, 2024, I spoke with Donna MacKenzie, a family physician from Ontario. Dr. MacKenzie was recently made aware of the College's concerns that he had prescribed a controlled substance to a patient in 2021. Her nurse Amy Sheffield advised me that he did have an undertaking with the College to not prescribe controlled substances."
result = deidentify(text)
print("Entities found:", result["result"]["summary"]["entities_found"])
print("De-identified text:", result["result"]["deidentified_text"])
print()
print("Detected entities:")
for h in result["result"]["highlights"]:
    val = text[h["start"]:h["end"]]
    print(f"  {h['entity_type']}: '{val}' (conf={h['confidence']:.2f})")
