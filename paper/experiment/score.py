#!/usr/bin/env python3
"""Score the three pre-registered models against measured residue.

Accuracy = fraction of measured cells where a model's pre-registered expected
class equals the measured outcome class. Reported per-layer and overall, per
time-point (T1 post-delete, T2 post-churn), with Clopper-Pearson *exact*
binomial 95% confidence intervals (scipy.stats.beta).

Pre-registration criterion (verbatim from §7): the two-axis model is a validated
predictor ONLY if it beats both baselines with non-overlapping intervals;
otherwise §2.2 stays descriptive organization.

Cells where either the prediction or the measurement is "na" (APFS L2) are
excluded from that model's denominator.
"""
import json
import os
import sys

from scipy.stats import beta

import predictions as P

WORKROOT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/delexp"
LAYERS = ["l1", "l2", "l3"]


def cp_interval(k, n, alpha=0.05):
    """Clopper-Pearson exact 95% CI for k successes in n trials."""
    if n == 0:
        return (float("nan"), float("nan"))
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return (lo, hi)


def load_measured():
    """cell 'fs|fid|layer' -> {t1: class, t2: class}."""
    meas = {}
    for fs in P.FS_LIST:
        path = os.path.join(WORKROOT, fs, f"measured_{fs}.json")
        m = json.load(open(path))
        for fid, r in m["files"].items():
            for layer in LAYERS:
                cell = f"{fs}|{fid}|{layer}"
                meas[cell] = {tp: r[tp].get(layer, "na") for tp in ("t1", "t2")}
    return meas


def score(preds, meas, tp):
    rows = {}
    for model in P.MODELS:
        per_layer = {L: [0, 0] for L in LAYERS}   # [hits, n]
        overall = [0, 0]
        for cell, mp in preds.items():
            fs, fid, layer = cell.split("|")
            pred = mp[model]
            m = meas[cell][tp]
            if pred == "na" or m == "na":
                continue
            per_layer[layer][1] += 1
            overall[1] += 1
            if pred == m:
                per_layer[layer][0] += 1
                overall[0] += 1
        rows[model] = {"per_layer": per_layer, "overall": overall}
    return rows


def fmt(k, n):
    acc = k / n if n else float("nan")
    lo, hi = cp_interval(k, n)
    return f"{k:2d}/{n:2d} = {acc*100:5.1f}%  [{lo*100:4.1f}, {hi*100:5.1f}]"


def main():
    preds = P.all_predictions()
    meas = load_measured()
    out = {}
    for tp in ("t1", "t2"):
        rows = score(preds, meas, tp)
        out[tp] = {}
        print(f"\n================  TIME-POINT {tp.upper()}  ================")
        header = f"{'model':10s}  {'L1 name':28s}  {'L2 map':28s}  {'L3 content':28s}  {'OVERALL':28s}"
        print(header)
        for model, r in rows.items():
            pl = r["per_layer"]
            ov = r["overall"]
            print(f"{model:10s}  "
                  f"{fmt(*pl['l1']):28s}  {fmt(*pl['l2']):28s}  "
                  f"{fmt(*pl['l3']):28s}  {fmt(*ov):28s}")
            out[tp][model] = {
                "per_layer": {L: {"hits": pl[L][0], "n": pl[L][1],
                                  "ci": cp_interval(*pl[L])} for L in LAYERS},
                "overall": {"hits": ov[0], "n": ov[1], "ci": cp_interval(*ov)},
            }
        # verdict on the pre-registered criterion (overall, this time-point)
        t = rows["two_axis"]["overall"]
        a = rows["axis_a"]["overall"]
        c = rows["carrier"]["overall"]
        t_ci = cp_interval(*t)
        a_ci = cp_interval(*a)
        c_ci = cp_interval(*c)
        beats_a = t[0] / t[1] > a[0] / a[1] and t_ci[0] > a_ci[1]
        beats_c = t[0] / t[1] > c[0] / c[1] and t_ci[0] > c_ci[1]
        verdict = ("VALIDATED PREDICTOR" if (beats_a and beats_c)
                   else "DESCRIPTIVE ORGANIZATION (does not beat both baselines "
                        "with non-overlapping intervals)")
        print(f"  -> two-axis higher than baselines: "
              f"{t[0]/t[1] > a[0]/a[1] and t[0]/t[1] > c[0]/c[1]}; "
              f"non-overlapping CIs: {beats_a and beats_c}  => {verdict}")
        out[tp]["verdict"] = verdict
    with open(os.path.join(WORKROOT, "score_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {WORKROOT}/score_results.json")


if __name__ == "__main__":
    main()
