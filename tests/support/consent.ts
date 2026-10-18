// Журнал согласий в памяти для тестов шлюза, которым мандаты не нужны (PaoDeps.consent обязателен).
import { ConsentJournal, MemoryConsentStore } from "../../src/consent/index.js";

export const memoryConsent = (): ConsentJournal => new ConsentJournal(new MemoryConsentStore(), { revocationOrder: () => "bank:test:revocation:v1" });
