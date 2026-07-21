import { Detector } from "../../types.js";
import { unicodeDetector } from "./unicode.js";
import { hiddenDetector } from "./hidden.js";
import { encodedDetector } from "./encoded.js";
import { homoglyphDetector } from "./homoglyph.js";
import { imperativesDetector } from "./imperatives.js";

// Register detectors here. All deterministic — no model in the loop, so a
// hostile repo cannot prompt-inject the scanner. The isolated classifier
// (opt-in, tool-less) lands next; see PLAN.md.
export const detectors: Detector[] = [
  unicodeDetector,
  hiddenDetector,
  encodedDetector,
  homoglyphDetector,
  imperativesDetector,
];
