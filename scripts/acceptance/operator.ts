// Порт оператора приёмки песочницы (SANDBOX-ACC, вариант В — решение владельца 28.10): допуск и отзыв — программой
// operator.mjs поверх dist установленной версии, журнал текущего запуска и перезапуск сервиса. На VPS — по ssh: программа
// копируется во временный каталог пользователя сервиса и удаляется в close(); установка не меняется. В CI — тот же
// operator.mjs локально (tests/unit/acceptance.test.ts). Закрытые ключи агента в порт не передаются: только заявление
// с открытым ключом и CSR.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Ответ operator.mjs на допуск: решение реестра, сертификат — открытый, DER в base64. */
export interface AdmitReply {
  readonly admitted: boolean;
  readonly reasons?: readonly string[];
  readonly agent_code?: string;
  readonly certificate?: { readonly serial: string; readonly der: string; readonly not_after: string };
}

export interface OperatorPort {
  /** Допуск в контуре sandbox оператором op-acceptance; CSR обязателен (РП66 п. 3). */
  admit(application: Record<string, unknown>): Promise<AdmitReply>;
  /** Отзыв сертификата по серийному номеру; true — отозван (теперь или раньше). */
  revoke(serial: string): Promise<boolean>;
  /** Журнал текущего запуска сервиса — строки, как их вывел процесс. */
  journal(): Promise<string>;
  /** Перезапуск сервиса; готовность ждёт скрипт приёмки. */
  restart(): Promise<void>;
  /** Удалить временное (каталог программы на VPS). */
  close(): Promise<void>;
}

export interface ExecResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}
export type Exec = (cmd: string, args: readonly string[], input?: string, env?: NodeJS.ProcessEnv) => Promise<ExecResult>;

/** Запуск без оболочки; input — в stdin; env — окружение целиком (по умолчанию — наследуется). */
export const spawnExec: Exec = (cmd, args, input, env) =>
  new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"], ...(env ? { env } : {}) });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    p.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    p.once("error", reject);
    p.once("close", (code) => resolve({ code, stdout, stderr }));
    // Процесс может выйти, не прочитав ввод (operator.mjs на SCHEMA_NOT_READY): EPIPE — не сбой, итог — код и вывод.
    p.stdin.on("error", (e: NodeJS.ErrnoException) => {
      if (e.code !== "EPIPE") reject(e);
    });
    p.stdin.end(input ?? "");
  });

export const OPERATOR_PROGRAM = fileURLToPath(new URL("./operator.mjs", import.meta.url));

export class OperatorError extends Error {
  constructor(readonly step: string, readonly code: string) {
    super(`оператор: ${step}: ${code}`);
    this.name = "OperatorError";
  }
}

/** Последняя строка JSON вывода operator.mjs; { error } или сбой разбора — OperatorError. */
export function parseReply(step: string, r: ExecResult): Record<string, unknown> {
  const line = r.stdout.trim().split("\n").pop() ?? "";
  let body: unknown;
  try {
    body = JSON.parse(line);
  } catch {
    throw new OperatorError(step, `EXIT_${r.code ?? "SIGNAL"}`);
  }
  if (typeof body !== "object" || body === null) throw new OperatorError(step, "REPLY_INVALID");
  const b = body as Record<string, unknown>;
  if (typeof b.error === "string") throw new OperatorError(step, b.error);
  if (r.code !== 0) throw new OperatorError(step, `EXIT_${r.code ?? "SIGNAL"}`);
  return b;
}

export interface SshOperatorOptions {
  /** Адрес ssh: host или user@host (ключ — в ssh-agent, без пароля: BatchMode). */
  readonly target: string;
  /** Корень установки Платформы на VPS (dist, node_modules, config). */
  readonly root: string;
  /** EnvironmentFile unit — те же переменные, что у сервиса. */
  readonly envFile: string;
  /** Имя unit systemd. */
  readonly unit: string;
  /** Пользователь сервиса: читает ключ УЦ и EnvironmentFile. */
  readonly user: string;
  readonly exec?: Exec;
  /** Текст программы; по умолчанию — operator.mjs рядом. */
  readonly program?: string;
}

// Части удалённой команды — только из безопасных символов: ssh склеивает аргументы в строку оболочки VPS. Ведущий «-»
// запрещён: значение стало бы ключом ssh или systemctl (КТ1 № 5); в имени unit нет и «/».
const SAFE = /^[A-Za-z0-9._/@:-]+$/;
const safe = (name: string, v: string): string => {
  if (!SAFE.test(v) || v.startsWith("-") || (name === "UNIT" && v.includes("/"))) throw new OperatorError("params", `UNSAFE_${name}`);
  return v;
};

export function sshOperator(o: SshOperatorOptions): OperatorPort {
  const target = safe("TARGET", o.target);
  const root = safe("ROOT", o.root);
  const envFile = safe("ENV_FILE", o.envFile);
  const unit = safe("UNIT", o.unit);
  const user = safe("USER", o.user);
  const exec = o.exec ?? spawnExec;
  const ssh = (remote: string, input?: string) => exec("ssh", ["-o", "BatchMode=yes", target, "--", remote], input);
  const asUser = `sudo -n -u ${user}`;
  let dir: string | undefined;

  const ensureProgram = async (): Promise<string> => {
    if (dir) return dir;
    const made = await ssh(`${asUser} mktemp -d`);
    const d = made.stdout.trim();
    if (made.code !== 0 || !SAFE.test(d) || !d.startsWith("/")) throw new OperatorError("mktemp", `EXIT_${made.code ?? "SIGNAL"}`);
    dir = d;
    const copied = await ssh(`${asUser} sh -c "cat > ${d}/operator.mjs"`, o.program ?? readFileSync(OPERATOR_PROGRAM, "utf8"));
    if (copied.code !== 0) throw new OperatorError("copy", `EXIT_${copied.code ?? "SIGNAL"}`);
    return d;
  };
  const run = async (step: string, request: Record<string, unknown>) =>
    parseReply(step, await ssh(`${asUser} node ${await ensureProgram()}/operator.mjs ${root} ${envFile}`, JSON.stringify(request)));

  return {
    admit: async (application) => (await run("admit", { cmd: "admit", application })) as unknown as AdmitReply,
    revoke: async (serial) => (await run("revoke", { cmd: "revoke", serial })).revoked === true,
    journal: async () => {
      // Журнал текущего запуска — по InvocationID unit, а не по времени: часы Mac и VPS не сравниваются.
      const shown = await ssh(`systemctl show -p InvocationID --value ${unit}`);
      const id = shown.stdout.trim();
      if (shown.code !== 0 || !/^[0-9a-f]{32}$/.test(id)) throw new OperatorError("journal", "INVOCATION_UNKNOWN");
      const j = await ssh(`journalctl _SYSTEMD_INVOCATION_ID=${id} -o cat --no-pager`);
      if (j.code !== 0) throw new OperatorError("journal", `EXIT_${j.code ?? "SIGNAL"}`);
      return j.stdout;
    },
    restart: async () => {
      const r = await ssh(`sudo -n systemctl restart ${unit}`);
      if (r.code !== 0) throw new OperatorError("restart", `EXIT_${r.code ?? "SIGNAL"}`);
    },
    close: async () => {
      if (!dir) return;
      const d = dir;
      dir = undefined;
      const r = await ssh(`${asUser} rm -rf ${d}`);
      if (r.code !== 0) throw new OperatorError("cleanup", `EXIT_${r.code ?? "SIGNAL"}`);
    },
  };
}
