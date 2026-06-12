// just-shield Action 진입점 (ADR-0004 엔진/포장 분리).
// 이 JS는 bash 스크립트를 부르는 얇은 디스패처일 뿐 — 판정 로직은 전부 Rust 바이너리에 있다.
// composite 액션은 잡 종료 훅(post)을 지원하지 않아, observe 모드의 "잡 끝에 보고"를
// 위해 node 진입점을 쓴다. 서드파티 npm 의존 0 — node 내장 모듈만 사용한다.
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");

// JS 액션은 GITHUB_ACTION_PATH가 없다(composite 전용) — 이 파일 위치가 곧 액션 루트.
const actionPath = __dirname;
const mode = process.env.INPUT_MODE || "scan";
const isPost = process.env.STATE_isPost === "true";

// main에서 상태를 남기면 runner가 post 호출 시 STATE_<name> 환경변수로 주입한다.
function saveState(name, value) {
  if (process.env.GITHUB_STATE) {
    fs.appendFileSync(process.env.GITHUB_STATE, `${name}=${value}\n`);
  }
}

// 자식 bash가 읽을 환경 — 액션 입력(INPUT_*)을 스크립트 규약(JS_*)으로 옮긴다.
const childEnv = {
  ...process.env,
  JS_VERSION: process.env.INPUT_VERSION || "",
  JS_PATH: process.env.INPUT_PATH || ".",
  JS_STRICT: process.env.INPUT_STRICT || "false",
  JS_ONLINE: process.env.INPUT_ONLINE || "false",
  JS_FORMAT: process.env.INPUT_FORMAT || "text",
  JS_COOLDOWN: process.env["INPUT_COOLDOWN-DAYS"] || "",
  JS_OUTPUT: process.env["INPUT_OUTPUT-FILE"] || "",
  JS_JOB: process.env.GITHUB_JOB || "job",
};

function runScript(name) {
  const r = spawnSync("bash", [`${actionPath}/scripts/${name}`], {
    stdio: "inherit",
    env: childEnv,
  });
  process.exit(r.status === null ? 1 : r.status);
}

if (!isPost) {
  // main 단계.
  saveState("isPost", "true"); // post가 반드시 호출되도록.
  if (mode === "observe") {
    // 관찰자를 백그라운드로 띄우고 즉시 빠진다 — 이후 사용자 스텝이 그 아래에서 돈다.
    runScript("observe-start.sh");
  } else {
    runScript("run.sh"); // scan — 동기 실행, 종료 코드 그대로.
  }
} else if (mode === "observe") {
  // post 단계 (observe 모드에서만 일한다) — 잡 끝에 보고/판정.
  runScript("observe-report.sh");
} else {
  process.exit(0); // scan 모드의 post는 할 일 없음.
}
