# -*- coding: utf-8 -*-
"""mklink 链接工具 — 单文件 / 零第三方依赖 / Python 3.14 + Tk 8.6

语义：
    左侧 = 已存在的源对象（mklink 的 Target T）
    右侧 = 新建链接所在位置（mklink 的 Link L）

重要（参数顺序陷阱）：
    mklink [opt] <Link> <Target>  是 Link 在前；
    本程序使用的 Python API 全部是 (target, link)，Target 在前。
    展示串由 format_mklink_command() 单独拼装，切勿与创建调用混用。

底层使用 Python 原生 API，不启动 cmd.exe / mklink，也不依赖 PowerShell
（仅当 _winapi.CreateJunction 不可用时才回退到 PowerShell）。
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import subprocess
import sys
import tkinter as tk
import winreg
from dataclasses import dataclass, field
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

try:
    import _winapi
except ImportError:  # pragma: no cover - 非 CPython Windows 环境
    _winapi = None


# ------------------------------------------------------------------ §1 常量
PARAM_NONE = "NONE"
PARAM_D = "D"
PARAM_H = "H"
PARAM_J = "J"


@dataclass(frozen=True)
class ParamInfo:
    key: str
    label: str
    flag: str
    needs_privilege: bool
    impl: str


PARAMS = {
    PARAM_NONE: ParamInfo(
        PARAM_NONE, "无参数（文件符号链接）", "", True,
        "os.symlink(target, link, target_is_directory=False)"),
    PARAM_D: ParamInfo(
        PARAM_D, "/D（目录符号链接）", "/D", True,
        "os.symlink(target, link, target_is_directory=True)"),
    PARAM_H: ParamInfo(
        PARAM_H, "/H（硬链接）", "/H", False,
        "os.link(target, link)"),
    PARAM_J: ParamInfo(
        PARAM_J, "/J（目录联接 junction）", "/J", False,
        "_winapi.CreateJunction(target, link)"),
}
LABEL_TO_KEY = {p.label: p.key for p in PARAMS.values()}

WINERR_MSG = {
    183: "同名链接/文件已存在，未覆盖、未改动",
    1314: "权限不足，请以管理员身份运行（或开启开发者模式）；未自动提权",
    5: "访问被拒绝，请以管理员身份运行；未自动提权",
    17: "硬链接不能跨卷，请改用「无参数」或把链接放在同卷",
    2: "链接父目录不存在，请重新选择",
    3: "链接父目录不存在，请重新选择",
}
SAFE_NOTE = "未删除/未替换任何文件，未自动提权"

UI_FONT = ("Microsoft YaHei UI", 10)


# ------------------------------------------------------ §2 环境与路径工具
def resource_path(rel: str) -> str:
    """资源定位：源码运行时取脚本同目录；PyInstaller 单文件模式取 _MEIPASS。"""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, rel)


def is_unc(path: str) -> bool:
    try:
        drive, _ = ntpath.splitdrive(ntpath.abspath(path))
    except (OSError, ValueError):
        return False
    return drive.startswith(("\\\\", "//"))


def same_volume(target: str, link_parent: str) -> bool:
    """用卷序列号判断同卷。

    必须用「链接父目录」而非链接本身：链接尚不存在，且符号链接的
    st_dev 会跟随目标卷，误用会得出错误结论。
    """
    try:
        return os.stat(target).st_dev == os.stat(link_parent).st_dev
    except OSError:
        return False


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def dev_mode() -> bool:
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(root, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "AllowDevelopmentWithoutDevLicense")
                if value == 1:
                    return True
        except OSError:
            continue
    return False


def can_symlink() -> bool:
    """仅用于界面提示，非权威；权威判定靠运行时 OSError.winerror。"""
    return is_admin() or dev_mode()


def basename_of(path: str) -> str:
    return ntpath.basename(path.rstrip("\\/"))


# -------------------------------------------------------- §3 决策与校验
@dataclass
class Decision:
    allowed: list[str] = field(default_factory=list)
    recommended: str | None = None
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    same_volume: bool = False
    left_is_dir: bool = False
    unc: bool = False


def decision_matrix(left: str, link_parent: str) -> Decision:
    """按左侧对象类型、是否同卷、是否 UNC 给出合法参数集与推荐项。

    合法集优先选免提权项：/H > 无参数，/J > /D。
    /J 的「源必须是已存在本地目录」由本函数与 validate_all 共同强制，
    因为 _winapi.CreateJunction 底层并不校验目标类型。
    """
    left_is_dir = os.path.isdir(left)
    unc = is_unc(left) or is_unc(link_parent)
    same = (not unc) and same_volume(left, link_parent)
    d = Decision(same_volume=same, left_is_dir=left_is_dir, unc=unc)

    if left_is_dir:
        if unc:
            d.allowed = [PARAM_D]
            d.recommended = PARAM_D
            d.reasons = [
                "/J：目录联接不支持 UNC 目标",
                "/H：硬链接不支持目录",
                "无参数：仅用于文件",
            ]
            d.notes.append("远程符号链接受 SMB 策略限制，可能失败")
        else:
            d.allowed = [PARAM_J, PARAM_D]
            d.recommended = PARAM_J
            d.reasons = ["/H：硬链接不支持目录", "无参数：仅用于文件"]
            d.notes.append("junction 可跨本地卷且免提权")
    else:
        d.reasons = ["/D、/J：链接目标必须是目录"]
        if not unc and same:
            d.allowed = [PARAM_H, PARAM_NONE]
            d.recommended = PARAM_H
            d.notes.append("同卷硬链接免提权，优先推荐")
        elif not unc:
            d.allowed = [PARAM_NONE]
            d.recommended = PARAM_NONE
            d.reasons.insert(0, "/H：硬链接不能跨卷")
            d.notes.append("跨卷只能用文件符号链接")
        else:
            d.allowed = [PARAM_NONE]
            d.recommended = PARAM_NONE
            d.reasons.insert(0, "/H：要求本地同卷 NTFS")
            d.notes.append("远程符号链接受 SMB 策略限制，可能失败")
    return d


def resolve_link_path(right_raw: str, right_mode: str, left: str) -> str:
    """混合语义：右侧选目录 = 存放目录（自动沿用左侧名称）；选文件 = 完整链接路径。"""
    if right_mode == "dir":
        return ntpath.normpath(ntpath.join(right_raw, basename_of(left)))
    return ntpath.normpath(right_raw)


@dataclass
class LinkRequest:
    left: str = ""
    right_raw: str = ""
    right_mode: str = ""
    param: str = ""
    link: str = ""


def validate_all(req: LinkRequest) -> tuple[bool, str | None]:
    """点击「链接」前的九步短路校验；成功时把推导出的 link 写回 req。"""
    if not req.left:
        return False, "请先在左侧选择源对象（Target）"
    if not os.path.lexists(req.left):
        return False, f"源对象不存在：{req.left}"
    if not os.path.exists(req.left):
        return False, f"源对象是悬空链接或不可访问：{req.left}"
    if not req.right_raw:
        return False, "请先在右侧选择链接位置（Link）"

    left_is_dir = os.path.isdir(req.left)
    link = resolve_link_path(req.right_raw, req.right_mode, req.left)
    link_parent = ntpath.dirname(link)
    if not os.path.isdir(link_parent):
        return False, f"链接父目录不存在：{link_parent}"
    if ntpath.abspath(link) == ntpath.abspath(req.left):
        return False, "链接路径与源对象相同，会造成自链接"
    if os.path.lexists(link):
        return False, f"同名链接/文件已存在，未覆盖、未改动：{link}"

    if req.param not in PARAMS:
        return False, "请选择链接参数"
    info = PARAMS[req.param]
    if left_is_dir and req.param in (PARAM_NONE, PARAM_H):
        return False, f"{info.label} 只适用于文件，源对象是目录"
    if (not left_is_dir) and req.param in (PARAM_D, PARAM_J):
        return False, f"{info.label} 只适用于目录，源对象是文件"

    if req.param == PARAM_H:
        if is_unc(req.left) or is_unc(link_parent):
            return False, "硬链接要求本地同卷，不支持 UNC 路径"
        if not same_volume(req.left, link_parent):
            return False, "硬链接不能跨卷，请改用「无参数」或把链接放在同卷"
    if req.param == PARAM_J:
        if is_unc(req.left) or is_unc(link_parent):
            return False, "目录联接 /J 不支持 UNC 目标或路径"
        if not os.path.isdir(req.left):
            return False, "/J 要求源对象为已存在的本地目录"

    req.link = link
    return True, None


def format_mklink_command(param: str, target: str, link: str) -> str:
    """仅用于日志展示，绝不执行。mklink 语法是 <Link> <Target>（Link 在前）。"""
    parts = ["mklink"]
    flag = PARAMS[param].flag
    if flag:
        parts.append(flag)
    parts.append(f'"{link}"')
    parts.append(f'"{target}"')
    return " ".join(parts)


# ------------------------------------------------------------ §4 创建层
@dataclass
class Result:
    ok: bool
    winerror: int | None = None
    msg: str = ""


def _create_junction_powershell(target: str, link: str) -> Result:
    """_winapi.CreateJunction 缺失时的降级路径（junction 免提权，回退安全）。"""
    pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe"
    exe = pwsh if os.path.isfile(pwsh) else "powershell.exe"
    t = target.replace("'", "''")
    l = link.replace("'", "''")
    script = f"New-Item -ItemType Junction -Path '{l}' -Target '{t}' | Out-Null"
    try:
        cp = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as e:
        return Result(False, getattr(e, "winerror", None), f"回退调用失败：{e}")
    if cp.returncode != 0:
        detail = (cp.stderr or cp.stdout).strip() or "PowerShell 回退失败"
        return Result(False, None, detail)
    return Result(True, None, "成功（PowerShell 回退创建 junction）")


def create_link(param: str, target: str, link: str) -> Result:
    """统一创建入口。所有分支的参数顺序都是 (target, link)，与 mklink 相反。

    绝不覆盖、绝不删除同名项、绝不自动提权、绝不自动重试。
    """
    try:
        if param == PARAM_H:
            os.link(target, link)
        elif param == PARAM_NONE:
            os.symlink(target, link, target_is_directory=False)
        elif param == PARAM_D:
            os.symlink(target, link, target_is_directory=True)
        elif param == PARAM_J:
            if _winapi is not None and hasattr(_winapi, "CreateJunction"):
                _winapi.CreateJunction(target, link)
            else:
                return _create_junction_powershell(target, link)
        else:
            return Result(False, None, f"未知参数：{param}")
    except OSError as e:
        code = getattr(e, "winerror", None)
        return Result(False, code, WINERR_MSG.get(code, f"{e}"))
    except Exception as e:  # 非 OSError 的意外异常，同样不做任何清理
        return Result(False, None, f"创建失败：{e}")
    return Result(True, None, "成功")


def describe_created(link: str) -> str:
    isjunction = getattr(os.path, "isjunction", lambda p: False)
    if isjunction(link):
        return "Junction（目录联接）"
    if os.path.islink(link):
        return "SymbolicLink（符号链接）"
    try:
        n = os.stat(link).st_nlink
        if n > 1:
            return f"HardLink（硬链接，链接数 {n}）"
    except OSError:
        pass
    return "已创建"


# --------------------------------------------------------------- §5 GUI
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("mklink 链接工具")
        self._apply_icon()
        self.geometry("980x620")
        self.minsize(900, 520)
        self._init_style()
        self._init_vars()
        self._build_ui()
        self.refresh_permission()
        self.recompute()

    def _apply_icon(self) -> None:
        """设置窗口/任务栏图标；图标缺失时静默跳过，不影响原有功能。"""
        ico = resource_path("mklink.ico")
        if not os.path.isfile(ico):
            return
        try:
            self.iconbitmap(ico)
        except (tk.TclError, OSError):
            pass

    def _init_style(self) -> None:
        style = ttk.Style(self)
        for name in ("TLabel", "TButton", "TEntry", "TCombobox", "TLabelframe.Label"):
            try:
                style.configure(name, font=UI_FONT)
            except tk.TclError:
                pass

    def _init_vars(self) -> None:
        self.var_left = tk.StringVar()
        self.var_left_type = tk.StringVar(value="尚未选择")
        self.var_right = tk.StringVar()
        self.var_link = tk.StringVar(value="尚未解析")
        self.var_param = tk.StringVar()
        self.var_reason = tk.StringVar(value="请先选择左侧源对象与右侧链接位置")
        self.var_perm = tk.StringVar()
        self.var_status = tk.StringVar(value="就绪 · 未自动提权 · 未删除任何文件")
        self.right_mode = ""
        self.privileged = False

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=0, minsize=250)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(2, weight=1)

        top = ttk.Label(
            self,
            text="左 = 源对象 Target（已存在）    │    右 = 新建链接 Link（位置或完整路径）",
            anchor="center",
        )
        top.grid(row=0, column=0, columnspan=3, sticky="ew", padx=12, pady=(12, 4))

        self._build_left()
        self._build_mid()
        self._build_right()
        self._build_log()

        status = ttk.Label(self, textvariable=self.var_status, anchor="w")
        status.grid(row=3, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 10))

    def _build_left(self) -> None:
        f = ttk.LabelFrame(self, text="① 左侧：源对象 Target", padding=10)
        f.grid(row=1, column=0, sticky="nsew", padx=(12, 6), pady=6)
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Button(row, text="选择文件", command=self.on_pick_left_file).pack(
            side="left", expand=True, fill="x", padx=(0, 4))
        ttk.Button(row, text="选择目录", command=self.on_pick_left_dir).pack(
            side="left", expand=True, fill="x", padx=(4, 0))
        ttk.Label(f, text="源对象路径（只读）").pack(anchor="w", pady=(12, 2))
        ttk.Entry(f, textvariable=self.var_left, state="readonly").pack(fill="x")
        ttk.Label(f, textvariable=self.var_left_type, foreground="#185FA5",
                  wraplength=250).pack(anchor="w", pady=(8, 0))

    def _build_mid(self) -> None:
        f = ttk.LabelFrame(self, text="② 链接设置", padding=10)
        f.grid(row=1, column=1, sticky="nsew", padx=6, pady=6)
        ttk.Label(f, text="→链接到", font=("Microsoft YaHei UI", 14)).pack(pady=(0, 10))
        self.cmb = ttk.Combobox(f, state="readonly", textvariable=self.var_param, values=[])
        self.cmb.pack(fill="x")
        ttk.Label(f, textvariable=self.var_reason, wraplength=210,
                  foreground="#854F0B").pack(fill="x", pady=(8, 12))
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Button(row, text="链接", command=self.on_link).pack(
            side="left", expand=True, fill="x", padx=(0, 4))
        ttk.Button(row, text="重置", command=self.on_reset).pack(
            side="left", expand=True, fill="x", padx=(4, 0))
        ttk.Label(f, textvariable=self.var_perm, wraplength=210,
                  foreground="#5F5E5A").pack(fill="x", pady=(12, 0))

    def _build_right(self) -> None:
        f = ttk.LabelFrame(self, text="③ 右侧：链接位置 Link", padding=10)
        f.grid(row=1, column=2, sticky="nsew", padx=(6, 12), pady=6)
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Button(row, text="选择文件", command=self.on_pick_right_file).pack(
            side="left", expand=True, fill="x", padx=(0, 4))
        ttk.Button(row, text="选择目录", command=self.on_pick_right_dir).pack(
            side="left", expand=True, fill="x", padx=(4, 0))
        ttk.Label(f, text="所选位置（只读）").pack(anchor="w", pady=(12, 2))
        ttk.Entry(f, textvariable=self.var_right, state="readonly").pack(fill="x")
        ttk.Label(f, textvariable=self.var_link, wraplength=250,
                  foreground="#185FA5").pack(anchor="w", pady=(8, 0))
        ttk.Label(f, text="选文件 = 另存为，可输入新名称；选目录 = 存放目录，自动沿用左侧名称",
                  wraplength=250, foreground="#5F5E5A").pack(anchor="w", pady=(6, 0))

    def _build_log(self) -> None:
        f = ttk.LabelFrame(self, text="结果 / 日志", padding=8)
        f.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=12, pady=6)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        self.txt_log = tk.Text(f, height=9, wrap="word", state="disabled",
                               font=("Consolas", 10))
        sb = ttk.Scrollbar(f, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb.set)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")

    # ------------------------------------------------------------ 事件
    def log(self, level: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", f"[{ts}] [{level}] {msg}\n")
        self.txt_log.configure(state="disabled")
        self.txt_log.see("end")

    def refresh_permission(self) -> None:
        self.privileged = can_symlink()
        self.var_perm.set(
            "已取得管理员权限（或开发者模式）" if self.privileged
            else "未提权：符号链接（无参数 / /D）可能失败，请以管理员身份运行"
        )

    def recompute(self) -> None:
        """任一选择变化后刷新：路径显示、决策矩阵、下拉合法项、权限徽标。"""
        left = self.var_left.get().strip()
        right = self.var_right.get().strip()
        if left:
            kind = "目录" if os.path.isdir(left) else "文件"
            drive = ntpath.splitdrive(ntpath.abspath(left))[0] or "—"
            extra = " · UNC 路径" if is_unc(left) else ""
            self.var_left_type.set(f"类型：{kind} · 卷 {drive}{extra}")
        else:
            self.var_left_type.set("尚未选择")

        if not (left and right):
            self.cmb.configure(values=[])
            self.var_param.set("")
            self.var_reason.set("请先选择左侧源对象与右侧链接位置")
            self.var_link.set("尚未解析")
            return

        link = resolve_link_path(right, self.right_mode, left)
        self.var_link.set(f"解析后 Link：{link}")
        parent = ntpath.dirname(link)
        d = decision_matrix(left, parent) if os.path.isdir(parent) else Decision()
        self.cmb.configure(values=[PARAMS[k].label for k in d.allowed])

        if d.recommended:
            self.var_param.set(PARAMS[d.recommended].label)
            why = d.notes[0] if d.notes else "当前组合最优"
            lines = [f"推荐 {PARAMS[d.recommended].flag or '无参数'}：{why}"]
        else:
            self.var_param.set("")
            lines = ["链接父目录不存在，无法推荐参数"]
        if d.reasons:
            lines.append("已禁用 " + "；".join(d.reasons))
        if d.notes[1:]:
            lines.extend(d.notes[1:])
        self.var_reason.set("\n".join(lines))
        self.refresh_permission()

    def on_pick_left_file(self) -> None:
        p = filedialog.askopenfilename(title="选择源对象（已存在的文件）")
        if p:
            self.var_left.set(ntpath.normpath(p))
            self.recompute()

    def on_pick_left_dir(self) -> None:
        p = filedialog.askdirectory(title="选择源对象（已存在的目录）", mustexist=True)
        if p:
            self.var_left.set(ntpath.normpath(p))
            self.recompute()

    def on_pick_right_file(self) -> None:
        p = filedialog.asksaveasfilename(
            title="指定链接的完整路径（可输入尚不存在的新名称）",
            confirmoverwrite=False,
        )
        if p:
            self.var_right.set(ntpath.normpath(p))
            self.right_mode = "file"
            self.recompute()

    def on_pick_right_dir(self) -> None:
        p = filedialog.askdirectory(title="选择链接的存放目录", mustexist=True)
        if p:
            self.var_right.set(ntpath.normpath(p))
            self.right_mode = "dir"
            self.recompute()

    def on_reset(self) -> None:
        """只清空界面状态与日志，绝不触碰文件系统。"""
        self.var_left.set("")
        self.var_left_type.set("尚未选择")
        self.var_right.set("")
        self.var_link.set("尚未解析")
        self.var_param.set("")
        self.var_reason.set("请先选择左侧源对象与右侧链接位置")
        self.right_mode = ""
        self.cmb.configure(values=[])
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.var_status.set("已重置（仅清空界面与日志，未改动任何文件）")
        self.refresh_permission()

    def on_link(self) -> None:
        req = LinkRequest(
            left=self.var_left.get().strip(),
            right_raw=self.var_right.get().strip(),
            right_mode=self.right_mode,
            param=LABEL_TO_KEY.get(self.var_param.get(), ""),
        )
        ok, err = validate_all(req)
        if not ok:
            self.log("失败", err or "校验未通过")
            self.var_status.set(err or "校验未通过")
            messagebox.showerror("无法创建", f"{err}\n\n{SAFE_NOTE}", parent=self)
            return

        info = PARAMS[req.param]
        cmd = format_mklink_command(req.param, req.left, req.link)
        self.log("准备", cmd)
        self.log("准备", f"实现：{info.flag or '无参数'} → {info.impl}")
        if info.needs_privilege and not self.privileged:
            self.log("提示", "当前未检测到创建符号链接所需权限；仍会尝试，但不会自动提权")

        result = create_link(req.param, req.left, req.link)
        if result.ok:
            detail = (f"{info.flag or '无参数'} → {describe_created(req.link)}；"
                      f"Link={req.link}；Target={req.left}")
            self.log("成功", detail)
            self.log("成功", result.msg)
            self.var_status.set("创建成功 · 未覆盖任何同名项")
            messagebox.showinfo("创建成功", f"{detail}\n\n等价命令：\n{cmd}", parent=self)
        else:
            extra = f"（winerror={result.winerror}）" if result.winerror is not None else ""
            msg = f"{result.msg}{extra}"
            self.log("失败", msg)
            self.var_status.set("创建失败 · 未改动任何文件")
            messagebox.showerror("创建失败", f"{msg}\n\n{SAFE_NOTE}", parent=self)


# -------------------------------------------------------------- §6 main
def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
