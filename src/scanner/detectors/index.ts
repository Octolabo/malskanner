import { Detector } from "../../types.js";
import { unicodeDetector } from "./unicode.js";
import { hiddenDetector } from "./hidden.js";
import { encodedDetector } from "./encoded.js";
import { homoglyphDetector } from "./homoglyph.js";

// Register detectors here. All Tier-1: pure, deterministic scanners with no
// model in the loop. Tier-2 heuristics + the isolated classifier land next
// (see PLAN.md).
export const detectors: Detector[] = [
  unicodeDetector,
  hiddenDetector,
  encodedDetector,
  homoglyphDetector,
];
