import logging
import re

import idaapi

from PySide6.QtWidgets import QApplication


PLUGIN_ID = "milankovo.paste_name"
PLUGIN_NAME = "Paste Name"
PLUGIN_VERSION = "1.0.1"
REPO_URL = "https://github.com/milankovo/paste_name"

logger = logging.getLogger("paste_name")
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


def paste():
    return QApplication.clipboard().text()


global last_vu


def rename(vu: idaapi.vdui_t, new_name: str):
    item: idaapi.ctree_item_t = vu.item
    if item.citype == idaapi.VDI_FUNC:
        logger.info("Renaming function @ 0x%x to %s", vu.cfunc.entry_ea, new_name)
        result = idaapi.force_name(vu.cfunc.entry_ea, "do_" + str(new_name))
        vu.refresh_view(False)
        return result
    lvar = item.get_lvar()
    if lvar:
        logger.info("Renaming lvar %s to %s", lvar.name, new_name)
        result = rename_lvar(vu, lvar, new_name)
        vu.refresh_ctext(False)
        return result
    e = item.e
    if e.op == idaapi.cot_obj:
        logger.info("Renaming obj @ 0x%x to %s", e.obj_ea, new_name)
        result = idaapi.force_name(e.obj_ea, str(new_name))
        vu.refresh_ctext(False)
        return result

    global last_vu

    last_vu = vu
    # ida version is greater or equal to 9.0

    """
    VDI_NONE = _ida_hexrays.VDI_NONE
VDI_EXPR = _ida_hexrays.VDI_EXPR
VDI_LVAR = _ida_hexrays.VDI_LVAR
VDI_FUNC = _ida_hexrays.VDI_FUNC
VDI_TAIL = _ida_hexrays.VDI_TAIL
    """

    citype_dict = {
        idaapi.VDI_NONE: "VDI_NONE",
        idaapi.VDI_EXPR: "VDI_EXPR",
        idaapi.VDI_LVAR: "VDI_LVAR",
        idaapi.VDI_FUNC: "VDI_FUNC",
        idaapi.VDI_TAIL: "VDI_TAIL",
    }
    citype_str = citype_dict.get(item.citype, "VDI_UNKNOWN")
    logger.debug("citype %s", citype_str)
    logger.debug("item '%s'", item.dstr())
    logger.debug("item.e.op %s", item.e.op)

    if hasattr(item, "get_udm") and hasattr(idaapi, "uint64_pointer"):
        udm = idaapi.udm_t()
        parent = idaapi.tinfo_t()
        p_offset = idaapi.uint64_pointer()
        idx = item.get_udm(udm, parent, p_offset.cast())
        if idx == -1:
            logger.warning("get_udm failed")
            return 0
        logger.debug("parent %s", parent.dstr())
        logger.debug("index %d", idx)
        logger.debug("p_offset %d", p_offset.value())
        logger.info("Renaming udm %s to %s", udm.name, new_name)

        ok2 = parent.rename_udm(idx, new_name)
        logger.debug("rename_udm returned %s = %s", ok2, idaapi.tinfo_errstr(ok2))

        if (new_type := type_for_name(new_name)) is not None:
            logger.info("Setting udm type to %s", new_type)
            ok3 = parent.set_udm_type(idx, new_type)
            logger.debug("set_udm_type returned %s = %s", ok3, idaapi.tinfo_errstr(ok3))
        else:
            logger.debug("No type for %s", new_name)
        vu.refresh_ctext(False)

    return 0


def make_pointer2(tif: idaapi.tinfo_t):
    if tif.empty() or tif.is_bitfield():
        return tif.get_stock(idaapi.STI_PVOID)

    ptr = idaapi.tinfo_t()
    if not ptr.create_ptr(tif):
        assert False
    return ptr


def type_for_name(s):
    til = idaapi.get_idati()
    named_type = idaapi.get_named_type(til, s, 0)
    if named_type is None:
        return None
    t = idaapi.tinfo_t()
    t.deserialize(til, named_type[1], named_type[2])
    try:
        return idaapi.make_pointer(t)
    except Exception:
        return make_pointer2(t)


def maybe_change_lvar_type(vu: idaapi.vdui_t, lvar: idaapi.lvar_t, name: str):
    tif = type_for_name(name)
    if tif is None:
        return
    vu.set_lvar_type(lvar, tif)


def rename_lvar(vu: idaapi.vdui_t, lvar, new_name):
    maybe_change_lvar_type(vu, lvar, new_name)

    if vu.rename_lvar(lvar, new_name, True):
        return True

    for i in range(20):
        name = "%s_%d" % (new_name, i)
        if vu.rename_lvar(lvar, name, True):
            return True
        # vu.set_lvar_type(lvar, name)
    return False


class paste_name_action_handler_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        vu: idaapi.vdui_t = idaapi.get_widget_vdui(ctx.widget)
        vu.get_current_item(idaapi.USE_KEYBOARD)
        # global last_vu
        # last_vu = vu
        # IDA accepts only 'char *' -> must use str()
        new_name = paste()
        if not new_name:
            return 0
        if new_name.startswith("import_"):
            new_name = new_name.replace("import_", "")

        new_name = re.sub(r"(_+\d+)+$", "", new_name, 0)
        if not new_name:
            return 0
        rename(vu, new_name)
        return 1

    def update(self, ctx):
        return (
            idaapi.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == idaapi.BWN_PSEUDOCODE
            else idaapi.AST_DISABLE_FOR_WIDGET
        )


class PastePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Paste clipboard text as names in the decompiler view."
    help = "Paste clipboard text as names in the decompiler view."
    wanted_name = "Paste Name"
    actname = "milankovo:paste-name"
    wanted_hotkey = ""

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = PLUGIN_ID
        addon.name = PLUGIN_NAME
        addon.producer = "Milankovo"
        addon.url = REPO_URL
        addon.version = PLUGIN_VERSION
        idaapi.register_addon(addon)
        if idaapi.init_hexrays_plugin():
            idaapi.register_action(
                idaapi.action_desc_t(
                    self.actname, "paste name", paste_name_action_handler_t(), "Ctrl+V"
                )
            )
        else:
            logger.warning("Hex-Rays is not available; skipping paste_name plugin")
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action(self.actname)
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return PastePlugin()
