# ShieldMCP experimental DistilBERT classifiers

Two local fine-tuned models derived from [distilbert-base-uncased](https://huggingface.co/distilbert/distilbert-base-uncased) (Apache-2.0; Sanh et al., 2019). ShieldMCP fine-tuning uses synthetic template-generated MCP content. These classifiers are experimental; scores are not probabilities of real-world harm or a compliance certification.

## Download the trained artifacts

The [v0.1.0-alpha.1 prerelease](https://github.com/saurabh-yergattikar/ShieldMCP/releases/tag/v0.1.0-alpha.1) contains final safetensors weights, tokenizers, configuration, recorded validation metrics and the synthetic dataset. Large weights are release assets rather than Git blobs. Training checkpoints and pickle-based training state are excluded.

From the repository root, install `pip install -e '.[ml]'`, download all release assets (through the browser or GitHub CLI), then verify checksums before extraction:

```bash
mkdir -p /tmp/shieldmcp-models
gh release download v0.1.0-alpha.1 --repo saurabh-yergattikar/ShieldMCP --dir /tmp/shieldmcp-models
(cd /tmp/shieldmcp-models && shasum -a 256 -c SHA256SUMS)
# Linux users can use sha256sum -c SHA256SUMS instead.
tar -xzf /tmp/shieldmcp-models/shieldmcp-stage1-classifier.tar.gz -C models
tar -xzf /tmp/shieldmcp-models/shieldmcp-stage3-token-classifier.tar.gz -C models
```

Run from the repository root or set absolute `SHIELDMCP_CLASSIFIER_MODEL` and `SHIELDMCP_TOKEN_CLASSIFIER_MODEL` environment paths. Runtime loading uses local files only. The framework evaluation refuses classifier/tiered runs when either trained detector is unavailable; the runtime stage wrappers may log and use heuristic fallback.

## Provenance and recorded metrics

| Model | Labels / task | Dataset split | Recorded synthetic validation |
|---|---|---|---|
| Stage 1 | 0 benign, 1 malicious tool description | 9,280 train / 1,160 validation / 1,160 test | Accuracy, precision, recall and F1: 1.0 |
| Stage 3 | O, B-INST, I-INST token tags | 5,600 train / 700 validation / 700 test | B-INST token F1: 0.998043; I-INST token F1: 1.0 |

These are saved training-time validation metrics, not newly measured held-out test performance. Stage 3 metrics are per-token, not entity/span F1 or attack success. Stage 1 metrics preserve the recorded arguments; complete Stage 3 run arguments were not saved in its metrics file. The artifact manifest records hashes; [metrics/](metrics/) preserves the original metric JSON files.

Exact content overlap exists across the synthetic splits: 86 Stage 1 validation entries and 85 test entries match training text; 2 Stage 3 validation entries match training token sequences. Shared templates also make nominally different examples similar. These splits are **not independently held-out attack families**, so near-perfect validation must not be presented as general security efficacy.

Both models truncate to 512 tokens. English template coverage does not establish robustness to unseen wording, multilingual inputs, encoded payloads, adaptive attackers or long content. A smoke test of the Stage 1 model scored an explicit malicious standalone sentence below its decision threshold; default structural checks still caught that input. Evaluate the complete configured pipeline as well as each learned component. Independent red-teaming is needed before deploying learned protection in a real workflow.

## Train instead

```bash
pip install -e '.[ml]'
python training/generate_stage1_data.py
python training/generate_stage3_data.py
python training/train_stage1.py --batch-size 32
python training/train_stage3.py --epochs 4
```

Data generation is local. Initial base-model retrieval requires network access. These commands retrain with the scripts' defaults; they are not a promise of bit-identical weights to the saved artifacts. Use the release dataset plus its manifest for exact input provenance. No production, eBay or Klira data was used by these template generators.

To inspect the released input files, extract `shieldmcp-synthetic-training-data.tar.gz` into `training/`; it creates `training/data/`. Add independent template/family-held-out evaluation when extending the models.

## License and attribution

ShieldMCP code and fine-tuned artifacts are distributed under Apache-2.0. Preserve the included LICENSE and this attribution to the DistilBERT base model and Victor Sanh, Lysandre Debut, Julien Chaumond and Thomas Wolf, *DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter* (2019). Upstream model limitations also apply. The artifact bundle does not include third-party Klira SDK code.
