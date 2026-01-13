from phi_pii_deidentifier import deidentify

# Exact text from the user's UI output
text = "On January 5, 2024, I spoke with Donna MacKenzie, a family physician from Ontario. Dr. MacKenzie was recently made aware of the College's concerns that he had prescribed a controlled substance to a patient in 2021. Her nurse Amy Sheffield advised me that he did have an undertaking with the College to not prescribe controlled substances."

result = deidentify(text)
print('Entities found:', result['result']['summary']['entities_found'])
print()
print('De-identified:')
print(result['result']['deidentified_text'])
print()
print('All highlights:')
for h in result['result']['highlights']:
    print(f'  {h["entity_type"]}: "{text[h["start"]:h["end"]]}" (conf={h["confidence"]:.2f})')
