// ВРЕМЕННО (К3.1а): подставная поломка «падение только на Node 20» — проверка итоговой test; отменяется git revert (К3.1б).
import { expect, it } from "vitest";

it("ВРЕМЕННО: поломка только на Node 20", () => {
  expect(process.versions.node.startsWith("20."), "подставная поломка К3.1а").toBe(false);
});
