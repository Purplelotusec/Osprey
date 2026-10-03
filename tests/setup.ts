import { httpRetryDefaults } from "../src/network/http.js";

// Tests stub fetch to fail on purpose; keep the retry behaviour but skip the waits.
httpRetryDefaults.retryDelayMs = 0;
