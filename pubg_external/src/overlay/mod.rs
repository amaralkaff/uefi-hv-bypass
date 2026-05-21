//! DX11 + ImGui overlay window. Layered transparent click-through topmost.
//! Uses random window class name to defeat Vanguard/BattlEye class-regex
//! match on "ImGui Platform" / "Dear ImGui".

mod window;
mod menu;

pub use window::run;
