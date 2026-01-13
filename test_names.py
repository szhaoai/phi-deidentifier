from phi_pii_deidentifier import deidentify

text = "On January 5, 2024, I spoke with Donna MacKenzie, a family physician from Ontario. Dr. MacKenzie was recently made aware of the College's concerns that he had prescribed a controlled substance to a patient in 2021. Her nurse Amy Sheffield advised me that he did have an undertaking with the College to not prescribe controlled substances."
#text = "On November 22, 2023, I had a callback for  Dr. Sherapartap Rai , a family doctor currently living in Brampton, Ontario, who signed an undertaking with CPSO to not prescribe controlled substances in 2011. The CPSO has accused Dr. Rai of breaching this undertaking. Dr. Rai contacted PC Dara Lambe, who had assisted him ton this file; she guided him to contact the Association to determine if we would extend assistance for this allegation of undertaking breach. The CPSO requires a response by November 24, 2023."
result = deidentify(text)
print("Entities found:", result["result"]["summary"]["entities_found"])
print("De-identified text:", result["result"]["deidentified_text"])
print()
print("Detected entities:")
for h in result["result"]["highlights"]:
    print(f"  {h['entity_type']}: '{text[h['start']:h['end']]}' (conf={h['confidence']:.2f})")
