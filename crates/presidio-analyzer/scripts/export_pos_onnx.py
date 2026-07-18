"""Export a UPOS token-classifier to ONNX + int8 dynamic-quantize, then measure size + CPU
speed (fp32 vs int8). Output dir ships `model.quant.onnx`, `tokenizer.json`, `id2label.json`
— exactly what the Rust `OnnxNlpEngine::from_dir` consumes.

Usage: python export_pos_onnx.py [HF_MODEL] [OUT_DIR]
  defaults: wietsedv/xlm-roberta-base-ft-udpos28-en  ./pos_onnx
Requires: transformers, optimum[onnxruntime], onnxruntime.
"""
import os, sys, time, json, shutil
from transformers import AutoTokenizer, AutoModelForTokenClassification
from optimum.onnxruntime import ORTModelForTokenClassification
from onnxruntime.quantization import quantize_dynamic, QuantType

MODEL = sys.argv[1] if len(sys.argv) > 1 else "wietsedv/xlm-roberta-base-ft-udpos28-en"
OUT = sys.argv[2] if len(sys.argv) > 2 else "./pos_onnx"
os.makedirs(OUT, exist_ok=True)

print("export fp32 onnx...", flush=True)
m = ORTModelForTokenClassification.from_pretrained(MODEL, export=True)
m.save_pretrained(OUT)
tok = AutoTokenizer.from_pretrained(MODEL)
tok.save_pretrained(OUT)
id2label = AutoModelForTokenClassification.from_pretrained(MODEL).config.id2label
json.dump({int(k): v for k, v in id2label.items()}, open(f"{OUT}/id2label.json", "w"))

fp32 = f"{OUT}/model.onnx"
int8 = f"{OUT}/model_int8.onnx"
print("int8 dynamic quantize...", flush=True)
quantize_dynamic(fp32, int8, weight_type=QuantType.QInt8)

sz32 = os.path.getsize(fp32) / 1e6
szq = os.path.getsize(int8) / 1e6
print(f"size: fp32={sz32:.0f}MB  int8={szq:.0f}MB  ({100*(1-szq/sz32):.0f}% smaller)", flush=True)

# CPU speed: fp32 vs int8
import onnxruntime as ort
sents = ["Rose called Mark about Section 3 and Milk prices in London",
         "Edward Bowen works at Titan Energy in Berlin"]


def speed(path, label):
    sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    inames = {i.name for i in sess.get_inputs()}
    t0 = time.time()
    for _ in range(20):
        for s in sents:
            enc = tok(s, return_tensors="np")
            sess.run(None, {k: v for k, v in enc.items() if k in inames})
    dt = time.time() - t0
    print(f"{label}: {20 * len(sents) / dt:.0f} sent/s", flush=True)


speed(fp32, "fp32")
speed(int8, "int8")
# ship only what the Rust OnnxNlpEngine needs
shutil.move(int8, f"{OUT}/model.quant.onnx")
print(f"\nshipped: {OUT}/model.quant.onnx + tokenizer.json + id2label.json", flush=True)
