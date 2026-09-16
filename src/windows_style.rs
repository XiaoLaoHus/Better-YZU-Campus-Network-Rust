//! Small, native GDI skin. Controls remain real Win32 edit/combo/button controls.
use native_windows_gui as nwg;
use winapi::shared::{minwindef::LRESULT, windef::{HDC, HWND, RECT}};
use winapi::um::{wingdi::*, winuser::*};

pub const BACKGROUND: [u8; 3] = [245, 246, 250];
pub const CARD: [u8; 3] = [255, 255, 255];

pub fn owner_draw(button: &nwg::Button) {
    unsafe {
        let hwnd = button.handle.hwnd().unwrap();
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        SetWindowLongPtrW(hwnd, GWL_STYLE, (style & !(BS_TYPEMASK as isize)) | BS_OWNERDRAW as isize);
    }
}

unsafe fn rounded(dc: HDC, rect: &RECT, radius: i32, color: u32) {
    let brush = CreateSolidBrush(color);
    let previous_brush = SelectObject(dc, brush as _);
    let previous_pen = SelectObject(dc, GetStockObject(NULL_PEN as i32));
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(dc, previous_pen);
    SelectObject(dc, previous_brush);
    DeleteObject(brush as _);
}

pub fn background(hwnd: HWND, dc: HDC) -> LRESULT {
    unsafe {
        let mut rect: RECT = std::mem::zeroed();
        GetClientRect(hwnd, &mut rect);
        let brush = CreateSolidBrush(RGB(245, 246, 250));
        FillRect(dc, &rect, brush);
        DeleteObject(brush as _);
        let scale = rect.right as f32 / 760.0;
        let px = |n: i32| (n as f32 * scale).round() as i32;
        for (top, bottom) in [(116, 348), (398, 570)] {
            let card = RECT { left: px(24), top: px(top), right: px(736), bottom: px(bottom) };
            rounded(dc, &card, px(24), RGB(255, 255, 255));
        }
    }
    1
}

pub fn button(lparam: isize, primary: HWND) -> Option<LRESULT> {
    unsafe {
        let item = &*(lparam as *const DRAWITEMSTRUCT);
        if item.CtlType != ODT_BUTTON { return None; }
        let saved = SaveDC(item.hDC);
        let disabled = item.itemState & ODS_DISABLED != 0;
        let pressed = item.itemState & ODS_SELECTED != 0;
        let accent = item.hwndItem == primary;
        let bg = if disabled { RGB(227, 230, 237) }
            else if accent && pressed { RGB(23, 67, 159) }
            else if accent { RGB(36, 91, 196) }
            else if pressed { RGB(219, 225, 237) }
            else { RGB(233, 237, 245) };
        // Clear the rectangular corners before drawing a rounded button.
        let brush = CreateSolidBrush(RGB(245, 246, 250));
        FillRect(item.hDC, &item.rcItem, brush);
        DeleteObject(brush as _);
        let height = item.rcItem.bottom - item.rcItem.top;
        rounded(item.hDC, &item.rcItem, height / 2, bg);
        SetBkMode(item.hDC, TRANSPARENT as i32);
        SetTextColor(item.hDC, if disabled { RGB(110, 116, 129) }
            else if accent { RGB(255, 255, 255) } else { RGB(38, 47, 65) });
        let font = SendMessageW(item.hwndItem, WM_GETFONT, 0, 0);
        if font != 0 { SelectObject(item.hDC, font as _); }
        let mut text = [0u16; 128];
        let length = GetWindowTextW(item.hwndItem, text.as_mut_ptr(), text.len() as i32);
        let mut rect = item.rcItem;
        DrawTextW(item.hDC, text.as_ptr(), length, &mut rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        if item.itemState & ODS_FOCUS != 0 {
            InflateRect(&mut rect, -5, -5);
            DrawFocusRect(item.hDC, &rect);
        }
        RestoreDC(item.hDC, saved);
    }
    Some(1)
}
