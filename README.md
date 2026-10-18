# WinARK_by_ase

**次世代 Windows 10/11 x64 純本地離線 Anti-Rootkit (ARK) 與內核分析工具集**

> 本專案融合當前多個頂級開源 ARK 專案之長處，構建為具備 **KMDF 宏門控驅動 + HMAC 安全令牌防禦 + 離線 Win11 時代特徵自適應 + 本地雙層特徵引擎 (SQLite + YARA)** 的新一代自研系統級安全分析工具。

---

## 📌 一、 組合來源與模組對照清單 (Upstream Origins & Code Sources)

本專案融合並改造了以下開源專案的核心技術與源碼模組，所有引用均符合其原作者之開源許可（MIT License）：

### 1. [mikasaw/MyArk](https://github.com/mikasaw/MyArk) (License: MIT)
* **引用路徑**：
  * `shared/driver/*`：統一的 R0/R3 IOCTL 協議與跨態數據結構。
  * `ring0/framework/*`：KMDF 非 PnP 控制設備、序列化隊列管理。
  * `ring0/dispatch/*`：IOCTL 查表、長度校驗與模組分發中心。
  * `ring0/modules/*`：31 個獨立功能模組（進程、線程、內存、句柄、回調、WFP、Win32k 等）。
  * `ring3/client/*`：Python 3.14 用戶態調度層與三欄式測試介面。
* **核心技術貢獻**：
  * **宏門控體系 (`#if MYARK_MODULE_*`)**：極度模組化，支援編譯期裁剪與自定義。
  * **`SAFETY_TOKEN` 安全模型**：基於每開機隨機會話密鑰之 HMAC-SHA256 安全令牌與 ±120s 防重放，杜絕被防毒軟體判定為惡意 BYOVD 工具。

### 2. [user-lzy/SnowSword](https://github.com/user-lzy/SnowSword) (License: MIT)
* **引用路徑**：
  * `ring0/offline_scanner/OffsetScanner.c / .h`：純本地離線內核偏移自適應掃描器。
  * `ring0/offline_scanner/Zydis.c / .h`：內嵌於驅動中的 Zydis 快速 x86/x64 反彙編引擎。
  * `SnowSwordCore/*`：IRP Dispatch MajorFunction 深度還原引擎庫。
* **核心技術貢獻**：
  * **純離線 Win11 24H2 適配**：劃分五大系統時代（`ERA_A` ~ `ERA_E`），無需對外聯網下載微軟 PDB 符號庫，即可在內核算出動態偏移。
  * **IRP 分發還原技術**：精準追溯 WDM、KMDF、WDDM 顯卡、HID 等驅動被 Rootkit 劫持前的真實分派指針。

### 3. [BeneficialCode/WinArk](https://github.com/BeneficialCode/WinArk) (License: MIT)
* **引用路徑**：
  * `ring3/phnt/*`：源自 Process Hacker 的完整 Native NT API 未文檔化原生結構體。
  * `ring3/pe_parser/*`：深度靜態 PE 結構分析器（DOS/NT 標頭、節區、IAT/EAT、導出導入表）。
* **核心技術貢獻**：
  * WTL (Windows Template Library) 極輕量化設計思維，使二進制檔案小於 3MB 且瞬間啟動。

### 4. 自研原創模組 (In-House Innovations)
* **引用路徑**：
  * `ring3/engine/db_engine.*`：本地 SQLite3 微秒級 Hash（MD5/SHA-256）白名單/黑名單過濾引擎。
  * `ring3/engine/yara_engine.*`：本地 YARA 記憶體深層掃描引擎（獵殺可疑 RWX 內存頁動態注入之 Shellcode）。
  * `database/`：純本地離線特徵資料庫與 YARA 規則庫目錄。

---

## 🏗️ 二、 系統架構總覽 (System Architecture)

```text
+------------------------------------------------------------------------+
|                 Ring 3 用戶態 (ArkGUI / ArkCLI / Python Client)         |
+------------------------------------------------------------------------+
|  [WTL 原生介面 / Python 介面]  <--->  [本地雙層特徵引擎 (SQLite + YARA)]  |
|                                                     |                  |
|  [PHNT 系統原生 API 宣告]      <--->  [SnowSwordCore IRP 還原庫]        |
+------------------------------------------------------------------------+
                                  |
                   [標準 DeviceIoControl 通訊協議]
             [+ HMAC-SHA256 SAFETY_TOKEN 變更操作保護]
                                  |
                                  v
+------------------------------------------------------------------------+
|                 Ring 0 內核態驅動 (ArkCore.sys - KMDF 現代架構)          |
+------------------------------------------------------------------------+
|  DriverEntry --> WdfDriverCreate --> WdfDeviceCreate ("\\.\ArkCore")   |
|                                                                        |
|  +-- dispatch/ (統一分發) -------------------------------------------+ |
|  |   ioctl_dispatch.c      -- 統一查表與完成                          | |
|  |   ioctl_validation.c    -- SAFETY_TOKEN 權限與緩衝區長度驗證        | |
|  |   ioctl_registry.c      -- 模組動態註冊表                          | |
|  +-------------------------------------------------------------------+ |
|                                                                        |
|  +-- offline_scanner/ (純離線適配引擎) ------------------------------+ |
|  |   OffsetScanner.c       -- 支援 Win10 ~ Win11 24H2 時代特徵自適應   | |
|  |   Zydis.c               -- 內核指令級動態跟蹤反彙編引擎            | |
|  +-------------------------------------------------------------------+ |
|                                                                        |
|  +-- modules/ (31 個功能模組, #if 宏門控) ---------------------------+ |
|  |   10_process            -- 活動鏈表 / PspCidTable 交叉取證         | |
|  |   12_memory             -- 虛擬地址翻譯 / 受限物理 RAM 讀取        | |
|  |   20_handle             -- 系統與進程句柄深度遍歷                  | |
|  |   71_callback           -- Ps/Cm/Ob/Image 回調枚舉與摘除           | |
|  |   72_wfp                -- WFP 網路過濾器與隱藏連接排查            | |
|  |   73_mutation           -- EPROCESS Token 提權與篡改偵測           | |
|  |   87_actions            -- 受 Token 保護之強殺進程與文件粉碎       | |
|  +-------------------------------------------------------------------+ |
+------------------------------------------------------------------------+
```

---

## 🛡️ 三、 安全模型與防防毒軟體 (Bitdefender) 誤殺對策

傳統 ARK 工具常被安全防護軟體（如 Bitdefender、Windows Defender）誤殺或封鎖，主要原因在於驅動暴露了未經保護的任意內存寫入或進程強殺 IOCTL，常被惡意軟體當作 **BYOVD (Bring Your Own Vulnerable Driver)** 工具。

本專案實施以下加固防護對策：
1. **設備句柄 SDDL 鎖定**：符號鏈接僅允許 `SYSTEM` 與具備管理員權限之進程開啟。
2. **HMAC-SHA256 會話令牌 (`SAFETY_TOKEN`)**：
   * 所有破壞性/敏感變更操作（如強殺進程、修改保護、內核寫入）必須攜帶開機時隨機密鑰生成的簽名 Token。
   * 內建 ±120 秒時間戳防重放機制，任何未經授權的第三方惡意軟體均無法濫用本驅動發動提權攻擊。
3. **動態 API 獲取**：用戶態二進制檔案不靜態導入敏感 API（如 `ZwTerminateProcess`），降低靜態特徵誤報。

---

## 🛠️ 四、 開發環境與編譯指南 (VS Code + MSBuild)

本專案完全適配在 **Visual Studio Code** 環境下進行模組化開發。

### 前置環境
1. **Visual Studio 2019 / 2022** (安裝 Desktop development with C++)
2. **Windows 10/11 WDK** (Windows Driver Kit)
3. **VS Code** (配置 C/C++ 擴展套件)

### 一鍵編譯流程
專案根目錄已內建 `.vscode/tasks.json`：
1. 在 VS Code 中按下 `Ctrl + Shift + B`（或選擇 `Terminal ➔ Run Build Task`）。
2. 可選構建任務：
   * **`Build Driver (KMDF Release x64)`**：一鍵編譯生成 `ArkCore.sys`。
   * **`Build SnowSwordCore (Dispatch Recovery DLL)`**：編譯生成 IRP 還原引擎動態庫。
   * **`Run Python Client (Test GUI)`**：啟動調試用戶態客戶端。

---

## ⚖️ 五、 許可證說明 (License)

本專案主體代碼與所有改編組件均遵循 **MIT License**。使用者可自由用於學術研究、個人安全分析、商業內部審計或進行二次開發。