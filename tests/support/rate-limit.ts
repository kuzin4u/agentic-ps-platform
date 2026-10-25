// Малый первый слой лимита ПАО для тестов (РП32): второй слой по уровням — 2 × n в минуту, n за окно 30 с, чтобы держать
// L3 / 2 ≤ pao_rate_limit_per_30s (РП63 доп. 1) и не срабатывать раньше первого слоя.
import { loadParams, type Params } from "../../src/shared/config.js";

export const coarseLimit = (n: number, base: Params = loadParams()): Params => ({
  ...base,
  pao_rate_limit_per_30s: n,
  pao_agent_rate_limit_per_min_l1: 2 * n,
  pao_agent_rate_limit_per_min_l2: 2 * n,
  pao_agent_rate_limit_per_min_l3: 2 * n,
});
