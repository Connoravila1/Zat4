//! B1 classification: SHELL (I/O — talks to the GPU driver). The GPU path.
//!
//! Dependency note (F1/F2): NO vendored package and NO link-time graphics
//! dependency. The system libraries libEGL / libGLESv2 are loaded at RUNTIME
//! with dlopen (the standard GL-loader pattern), so the app builds with only
//! libc and runs on any desktop that has a GPU driver — no -dev packages, no
//! build.zig.zon entry, no @cImport. The justification is the now-real
//! requirement the software renderer cannot meet: a full-window animated glyph
//! field at high-DPI, smoothly. The GPU is purpose-built for exactly that.
//!
//! On X11, EGL's native window IS the X Window XID, which the window backend
//! already hands us — so we need neither Xlib nor xcb.
//! eglGetDisplay(EGL_DEFAULT_DISPLAY) lets EGL open its own $DISPLAY
//! connection; we render to the existing window by its ID.
//!
//! FOUNDATION slice: load the entry points, create a context, clear, swap.
//! Atlas, shaders, and draw-list translation build on top once this is proven
//! on real hardware (it cannot be run in the build sandbox).

const std = @import("std");

extern fn dlopen(path: [*:0]const u8, mode: c_int) callconv(.c) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque;

// --- EGL / GLES2 handle and scalar types (C ABI) ---
const EGLDisplay = ?*anyopaque;
const EGLConfig = ?*anyopaque;
const EGLSurface = ?*anyopaque;
const EGLContext = ?*anyopaque;
const EGLBoolean = c_uint;
const EGLint = i32;
const EGLenum = c_uint;
const EGLNativeWindowType = c_ulong; // X11: the Window XID

const RTLD_NOW: c_int = 2;

// --- function-pointer types for the entry points we load (C ABI) ---
const P_GetDisplay = *const fn (?*anyopaque) callconv(.c) EGLDisplay;
const P_Initialize = *const fn (EGLDisplay, ?*EGLint, ?*EGLint) callconv(.c) EGLBoolean;
const P_BindAPI = *const fn (EGLenum) callconv(.c) EGLBoolean;
const P_ChooseConfig = *const fn (EGLDisplay, [*]const EGLint, [*]EGLConfig, EGLint, *EGLint) callconv(.c) EGLBoolean;
const P_GetConfigAttrib = *const fn (EGLDisplay, EGLConfig, EGLint, *EGLint) callconv(.c) EGLBoolean;
const P_CreateWindowSurface = *const fn (EGLDisplay, EGLConfig, EGLNativeWindowType, ?[*]const EGLint) callconv(.c) EGLSurface;
const P_CreateContext = *const fn (EGLDisplay, EGLConfig, EGLContext, ?[*]const EGLint) callconv(.c) EGLContext;
const P_MakeCurrent = *const fn (EGLDisplay, EGLSurface, EGLSurface, EGLContext) callconv(.c) EGLBoolean;
const P_SwapBuffers = *const fn (EGLDisplay, EGLSurface) callconv(.c) EGLBoolean;
const P_SwapInterval = *const fn (EGLDisplay, EGLint) callconv(.c) EGLBoolean;
const P_DestroySurface = *const fn (EGLDisplay, EGLSurface) callconv(.c) EGLBoolean;
const P_DestroyContext = *const fn (EGLDisplay, EGLContext) callconv(.c) EGLBoolean;
const P_Terminate = *const fn (EGLDisplay) callconv(.c) EGLBoolean;
const P_GetError = *const fn () callconv(.c) EGLint;
const P_ClearColor = *const fn (f32, f32, f32, f32) callconv(.c) void;
const P_Clear = *const fn (c_uint) callconv(.c) void;
const P_Viewport = *const fn (EGLint, EGLint, EGLint, EGLint) callconv(.c) void;
const P_GetString = *const fn (c_uint) callconv(.c) ?[*:0]const u8;

// Loaded entry points (filled by load()).
var eglGetDisplay: P_GetDisplay = undefined;
var eglInitialize: P_Initialize = undefined;
var eglBindAPI: P_BindAPI = undefined;
var eglChooseConfig: P_ChooseConfig = undefined;
var eglGetConfigAttrib: P_GetConfigAttrib = undefined;
var eglCreateWindowSurface: P_CreateWindowSurface = undefined;
var eglCreateContext: P_CreateContext = undefined;
var eglMakeCurrent: P_MakeCurrent = undefined;
var eglSwapBuffers: P_SwapBuffers = undefined;
var eglSwapInterval: P_SwapInterval = undefined;
var eglDestroySurface: P_DestroySurface = undefined;
var eglDestroyContext: P_DestroyContext = undefined;
var eglTerminate: P_Terminate = undefined;
var eglGetError: P_GetError = undefined;
var glClearColor: P_ClearColor = undefined;
var glClear: P_Clear = undefined;
var glViewport: P_Viewport = undefined;
var glGetString: P_GetString = undefined;

var loaded = false;

// --- constants (from the EGL/GL headers, declared here to avoid a header dep) ---
const EGL_NO_DISPLAY: EGLDisplay = null;
const EGL_NO_CONTEXT: EGLContext = null;
const EGL_NO_SURFACE: EGLSurface = null;
const EGL_TRUE: EGLBoolean = 1;
const EGL_OPENGL_ES_API: EGLenum = 0x30A0;
const EGL_SURFACE_TYPE: EGLint = 0x3033;
const EGL_WINDOW_BIT: EGLint = 0x0004;
const EGL_RENDERABLE_TYPE: EGLint = 0x3040;
const EGL_OPENGL_ES2_BIT: EGLint = 0x0004;
const EGL_RED_SIZE: EGLint = 0x3024;
const EGL_GREEN_SIZE: EGLint = 0x3023;
const EGL_BLUE_SIZE: EGLint = 0x3022;
const EGL_ALPHA_SIZE: EGLint = 0x3021;
const EGL_NONE: EGLint = 0x3038;
const EGL_CONTEXT_CLIENT_VERSION: EGLint = 0x3098;
const EGL_NATIVE_VISUAL_ID: EGLint = 0x302E;
const GL_COLOR_BUFFER_BIT: c_uint = 0x00004000;
const GL_VENDOR: c_uint = 0x1F00;
const GL_RENDERER: c_uint = 0x1F01;
const GL_VERSION: c_uint = 0x1F02;

pub const Error = error{GpuInit};

/// A live GL context bound to a window. Three opaque handles.
pub const Gpu = struct {
    dpy: EGLDisplay,
    surface: EGLSurface,
    context: EGLContext,

    comptime {
        std.debug.assert(@sizeOf(Gpu) == 24); // 3 pointers (A7)
    }
};

fn elog(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[gpu] " ++ fmt ++ "\n", args);
}

fn fail(comptime step: []const u8) Error {
    elog("{s} FAILED — eglGetError = 0x{x}", .{ step, @as(u32, @bitCast(eglGetError())) });
    return Error.GpuInit;
}

fn sym(lib: ?*anyopaque, comptime T: type, name: [*:0]const u8) Error!T {
    const p = dlsym(lib, name) orelse {
        elog("dlsym '{s}' not found", .{name});
        return Error.GpuInit;
    };
    return @ptrCast(p);
}

fn load() Error!void {
    if (loaded) return;
    const lib_egl = dlopen("libEGL.so.1", RTLD_NOW) orelse {
        elog("dlopen libEGL.so.1 failed (is a GPU driver installed?)", .{});
        return Error.GpuInit;
    };
    const lib_gl = dlopen("libGLESv2.so.2", RTLD_NOW) orelse {
        elog("dlopen libGLESv2.so.2 failed", .{});
        return Error.GpuInit;
    };
    eglGetDisplay = try sym(lib_egl, P_GetDisplay, "eglGetDisplay");
    eglInitialize = try sym(lib_egl, P_Initialize, "eglInitialize");
    eglBindAPI = try sym(lib_egl, P_BindAPI, "eglBindAPI");
    eglChooseConfig = try sym(lib_egl, P_ChooseConfig, "eglChooseConfig");
    eglGetConfigAttrib = try sym(lib_egl, P_GetConfigAttrib, "eglGetConfigAttrib");
    eglCreateWindowSurface = try sym(lib_egl, P_CreateWindowSurface, "eglCreateWindowSurface");
    eglCreateContext = try sym(lib_egl, P_CreateContext, "eglCreateContext");
    eglMakeCurrent = try sym(lib_egl, P_MakeCurrent, "eglMakeCurrent");
    eglSwapBuffers = try sym(lib_egl, P_SwapBuffers, "eglSwapBuffers");
    eglSwapInterval = try sym(lib_egl, P_SwapInterval, "eglSwapInterval");
    eglDestroySurface = try sym(lib_egl, P_DestroySurface, "eglDestroySurface");
    eglDestroyContext = try sym(lib_egl, P_DestroyContext, "eglDestroyContext");
    eglTerminate = try sym(lib_egl, P_Terminate, "eglTerminate");
    eglGetError = try sym(lib_egl, P_GetError, "eglGetError");
    glClearColor = try sym(lib_gl, P_ClearColor, "glClearColor");
    glClear = try sym(lib_gl, P_Clear, "glClear");
    glViewport = try sym(lib_gl, P_Viewport, "glViewport");
    glGetString = try sym(lib_gl, P_GetString, "glGetString");
    // Renderer entry points (Phase 6.1): shader program, one dynamic vertex
    // buffer, one atlas texture, one draw call. All in libGLESv2.
    glCreateShader = try sym(lib_gl, P_CreateShader, "glCreateShader");
    glShaderSource = try sym(lib_gl, P_ShaderSource, "glShaderSource");
    glCompileShader = try sym(lib_gl, P_CompileShader, "glCompileShader");
    glGetShaderiv = try sym(lib_gl, P_GetShaderiv, "glGetShaderiv");
    glGetShaderInfoLog = try sym(lib_gl, P_GetShaderInfoLog, "glGetShaderInfoLog");
    glCreateProgram = try sym(lib_gl, P_CreateProgram, "glCreateProgram");
    glAttachShader = try sym(lib_gl, P_AttachShader, "glAttachShader");
    glLinkProgram = try sym(lib_gl, P_LinkProgram, "glLinkProgram");
    glGetProgramiv = try sym(lib_gl, P_GetProgramiv, "glGetProgramiv");
    glGetProgramInfoLog = try sym(lib_gl, P_GetProgramInfoLog, "glGetProgramInfoLog");
    glUseProgram = try sym(lib_gl, P_UseProgram, "glUseProgram");
    glGenBuffers = try sym(lib_gl, P_GenBuffers, "glGenBuffers");
    glBindBuffer = try sym(lib_gl, P_BindBuffer, "glBindBuffer");
    glBufferData = try sym(lib_gl, P_BufferData, "glBufferData");
    glGetAttribLocation = try sym(lib_gl, P_GetAttribLocation, "glGetAttribLocation");
    glEnableVertexAttribArray = try sym(lib_gl, P_EnableVertexAttribArray, "glEnableVertexAttribArray");
    glVertexAttribPointer = try sym(lib_gl, P_VertexAttribPointer, "glVertexAttribPointer");
    glGenTextures = try sym(lib_gl, P_GenTextures, "glGenTextures");
    glBindTexture = try sym(lib_gl, P_BindTexture, "glBindTexture");
    glTexImage2D = try sym(lib_gl, P_TexImage2D, "glTexImage2D");
    glTexParameteri = try sym(lib_gl, P_TexParameteri, "glTexParameteri");
    glActiveTexture = try sym(lib_gl, P_ActiveTexture, "glActiveTexture");
    glPixelStorei = try sym(lib_gl, P_PixelStorei, "glPixelStorei");
    glGetUniformLocation = try sym(lib_gl, P_GetUniformLocation, "glGetUniformLocation");
    glUniform2f = try sym(lib_gl, P_Uniform2f, "glUniform2f");
    glUniform1f = try sym(lib_gl, P_Uniform1f, "glUniform1f");
    glUniform1i = try sym(lib_gl, P_Uniform1i, "glUniform1i");
    glEnable = try sym(lib_gl, P_Enable, "glEnable");
    glBlendFunc = try sym(lib_gl, P_BlendFunc, "glBlendFunc");
    glDrawArrays = try sym(lib_gl, P_DrawArrays, "glDrawArrays");
    glGetErrorGL = try sym(lib_gl, P_GetErrorGL, "glGetError");
    loaded = true;
}

/// Bring up an EGL/GLES2 context on the existing X11 window `wid`, with a
/// running commentary so a real-hardware run reports exactly where (if
/// anywhere) it stops. Returns a live, current context.
pub fn init(wid: u32) Error!Gpu {
    try load();

    const dpy = eglGetDisplay(null); // EGL_DEFAULT_DISPLAY → EGL opens its own $DISPLAY connection
    if (dpy == EGL_NO_DISPLAY) return fail("eglGetDisplay");

    var maj: EGLint = 0;
    var min: EGLint = 0;
    if (eglInitialize(dpy, &maj, &min) != EGL_TRUE) return fail("eglInitialize");
    elog("EGL {d}.{d} initialized", .{ maj, min });

    if (eglBindAPI(EGL_OPENGL_ES_API) != EGL_TRUE) return fail("eglBindAPI");

    const cfg_attribs = [_]EGLint{
        EGL_SURFACE_TYPE,    EGL_WINDOW_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE,        8,
        EGL_GREEN_SIZE,      8,
        EGL_BLUE_SIZE,       8,
        EGL_ALPHA_SIZE,      8,
        EGL_NONE,
    };
    var config: EGLConfig = null;
    var num: EGLint = 0;
    if (eglChooseConfig(dpy, &cfg_attribs, @ptrCast(&config), 1, &num) != EGL_TRUE or num < 1) return fail("eglChooseConfig");
    var vis: EGLint = 0;
    _ = eglGetConfigAttrib(dpy, config, EGL_NATIVE_VISUAL_ID, &vis);
    elog("chose config (native visual id = 0x{x}); window must use a matching visual", .{@as(u32, @bitCast(vis))});

    const ctx_attribs = [_]EGLint{ EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    const context = eglCreateContext(dpy, config, EGL_NO_CONTEXT, &ctx_attribs);
    if (context == EGL_NO_CONTEXT) return fail("eglCreateContext");

    const surface = eglCreateWindowSurface(dpy, config, @as(EGLNativeWindowType, wid), null);
    if (surface == EGL_NO_SURFACE) return fail("eglCreateWindowSurface");

    if (eglMakeCurrent(dpy, surface, surface, context) != EGL_TRUE) return fail("eglMakeCurrent");
    _ = eglSwapInterval(dpy, 1); // vsync

    if (glGetString(GL_VERSION)) |s| elog("GL_VERSION  = {s}", .{s});
    if (glGetString(GL_RENDERER)) |s| elog("GL_RENDERER = {s}", .{s});
    if (glGetString(GL_VENDOR)) |s| elog("GL_VENDOR   = {s}", .{s});
    elog("context is current — GPU path is live", .{});

    return .{ .dpy = dpy, .surface = surface, .context = context };
}

pub fn setViewport(w: i32, h: i32) void {
    glViewport(0, 0, w, h);
}

pub fn clear(r: f32, g: f32, b: f32) void {
    glClearColor(r, g, b, 1.0);
    glClear(GL_COLOR_BUFFER_BIT);
}

pub fn swap(self: *const Gpu) void {
    _ = eglSwapBuffers(self.dpy, self.surface);
}

pub fn deinit(self: *Gpu) void {
    _ = eglMakeCurrent(self.dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    _ = eglDestroySurface(self.dpy, self.surface);
    _ = eglDestroyContext(self.dpy, self.context);
    _ = eglTerminate(self.dpy);
}

// ===========================================================================
// THE RENDERER (Phase 6.1): the same draw list the software rasterizer
// consumes (raster.DrawItem), drawn on the GPU. Every item becomes a quad
// (6 vertices, two triangles) in ONE dynamic vertex buffer, drawn in ONE
// glDrawArrays call. Glyphs sample a single atlas texture (core/atlas.zig);
// rounded rects are an SDF in the fragment shader; lines and sharp fills are
// solid quads. Batched triangles over hardware instancing on purpose: it
// needs only plain GLES2 (no ES3 divisor) and the quad counts (a few
// thousand) make instancing's byte savings irrelevant (G3 — no optimization
// without a measurement that demands it).
//
// This stays inside the GPU module: the vertex layout, the shaders, and the
// draw-list→vertex translation are all the "rendering backend" decision
// (D1/D4), so the strong coupling between them never crosses a boundary. The
// only things that cross in are plain core values — DrawItems and atlas rects
// (B5).
// ===========================================================================

const raster = @import("../core/raster.zig");
const atlas_mod = @import("../core/atlas.zig");
const text = @import("../core/text.zig");
const field = @import("../core/field.zig");

// --- GL scalar types (C ABI) ---
const GLuint = c_uint;
const GLint = c_int;
const GLsizei = c_int;
const GLenum = c_uint;
const GLfloat = f32;
const GLchar = u8;
const GLboolean = u8;
const GLsizeiptr = isize;

// --- renderer entry-point types ---
const P_CreateShader = *const fn (GLenum) callconv(.c) GLuint;
const P_ShaderSource = *const fn (GLuint, GLsizei, [*]const [*:0]const GLchar, ?[*]const GLint) callconv(.c) void;
const P_CompileShader = *const fn (GLuint) callconv(.c) void;
const P_GetShaderiv = *const fn (GLuint, GLenum, *GLint) callconv(.c) void;
const P_GetShaderInfoLog = *const fn (GLuint, GLsizei, ?*GLsizei, [*]GLchar) callconv(.c) void;
const P_CreateProgram = *const fn () callconv(.c) GLuint;
const P_AttachShader = *const fn (GLuint, GLuint) callconv(.c) void;
const P_LinkProgram = *const fn (GLuint) callconv(.c) void;
const P_GetProgramiv = *const fn (GLuint, GLenum, *GLint) callconv(.c) void;
const P_GetProgramInfoLog = *const fn (GLuint, GLsizei, ?*GLsizei, [*]GLchar) callconv(.c) void;
const P_UseProgram = *const fn (GLuint) callconv(.c) void;
const P_GenBuffers = *const fn (GLsizei, [*]GLuint) callconv(.c) void;
const P_BindBuffer = *const fn (GLenum, GLuint) callconv(.c) void;
const P_BufferData = *const fn (GLenum, GLsizeiptr, ?*const anyopaque, GLenum) callconv(.c) void;
const P_GetAttribLocation = *const fn (GLuint, [*:0]const GLchar) callconv(.c) GLint;
const P_EnableVertexAttribArray = *const fn (GLuint) callconv(.c) void;
const P_VertexAttribPointer = *const fn (GLuint, GLint, GLenum, GLboolean, GLsizei, ?*const anyopaque) callconv(.c) void;
const P_GenTextures = *const fn (GLsizei, [*]GLuint) callconv(.c) void;
const P_BindTexture = *const fn (GLenum, GLuint) callconv(.c) void;
const P_TexImage2D = *const fn (GLenum, GLint, GLint, GLsizei, GLsizei, GLint, GLenum, GLenum, ?*const anyopaque) callconv(.c) void;
const P_TexParameteri = *const fn (GLenum, GLenum, GLint) callconv(.c) void;
const P_ActiveTexture = *const fn (GLenum) callconv(.c) void;
const P_PixelStorei = *const fn (GLenum, GLint) callconv(.c) void;
const P_GetUniformLocation = *const fn (GLuint, [*:0]const GLchar) callconv(.c) GLint;
const P_Uniform2f = *const fn (GLint, GLfloat, GLfloat) callconv(.c) void;
const P_Uniform1f = *const fn (GLint, GLfloat) callconv(.c) void;
const P_Uniform1i = *const fn (GLint, GLint) callconv(.c) void;
const P_Enable = *const fn (GLenum) callconv(.c) void;
const P_BlendFunc = *const fn (GLenum, GLenum) callconv(.c) void;
const P_DrawArrays = *const fn (GLenum, GLint, GLsizei) callconv(.c) void;
const P_GetErrorGL = *const fn () callconv(.c) GLenum;

var glCreateShader: P_CreateShader = undefined;
var glShaderSource: P_ShaderSource = undefined;
var glCompileShader: P_CompileShader = undefined;
var glGetShaderiv: P_GetShaderiv = undefined;
var glGetShaderInfoLog: P_GetShaderInfoLog = undefined;
var glCreateProgram: P_CreateProgram = undefined;
var glAttachShader: P_AttachShader = undefined;
var glLinkProgram: P_LinkProgram = undefined;
var glGetProgramiv: P_GetProgramiv = undefined;
var glGetProgramInfoLog: P_GetProgramInfoLog = undefined;
var glUseProgram: P_UseProgram = undefined;
var glGenBuffers: P_GenBuffers = undefined;
var glBindBuffer: P_BindBuffer = undefined;
var glBufferData: P_BufferData = undefined;
var glGetAttribLocation: P_GetAttribLocation = undefined;
var glEnableVertexAttribArray: P_EnableVertexAttribArray = undefined;
var glVertexAttribPointer: P_VertexAttribPointer = undefined;
var glGenTextures: P_GenTextures = undefined;
var glBindTexture: P_BindTexture = undefined;
var glTexImage2D: P_TexImage2D = undefined;
var glTexParameteri: P_TexParameteri = undefined;
var glActiveTexture: P_ActiveTexture = undefined;
var glPixelStorei: P_PixelStorei = undefined;
var glGetUniformLocation: P_GetUniformLocation = undefined;
var glUniform2f: P_Uniform2f = undefined;
var glUniform1f: P_Uniform1f = undefined;
var glUniform1i: P_Uniform1i = undefined;
var glEnable: P_Enable = undefined;
var glBlendFunc: P_BlendFunc = undefined;
var glDrawArrays: P_DrawArrays = undefined;
var glGetErrorGL: P_GetErrorGL = undefined;

// --- GL constants (from the GLES2 headers, declared to avoid a header dep) ---
const GL_FRAGMENT_SHADER: GLenum = 0x8B30;
const GL_VERTEX_SHADER: GLenum = 0x8B31;
const GL_COMPILE_STATUS: GLenum = 0x8B81;
const GL_LINK_STATUS: GLenum = 0x8B82;
const GL_ARRAY_BUFFER: GLenum = 0x8892;
const GL_DYNAMIC_DRAW: GLenum = 0x88E8;
const GL_STATIC_DRAW: GLenum = 0x88E4;
const GL_FLOAT: GLenum = 0x1406;
const GL_TRIANGLES: GLenum = 0x0004;
const GL_TEXTURE_2D: GLenum = 0x0DE1;
const GL_TEXTURE0: GLenum = 0x84C0;
const GL_LUMINANCE: GLenum = 0x1909;
const GL_UNSIGNED_BYTE: GLenum = 0x1401;
const GL_R32F: GLint = 0x822E; // single-channel float — the CPU field's height upload
const GL_RED: GLenum = 0x1903;
const GL_NEAREST_FILTER: GLint = 0x2600; // sample the field per cell, no interpolation
const GL_TEXTURE_MIN_FILTER: GLenum = 0x2801;
const GL_TEXTURE_MAG_FILTER: GLenum = 0x2800;
const GL_LINEAR: GLint = 0x2601;
const GL_TEXTURE_WRAP_S: GLenum = 0x2802;
const GL_TEXTURE_WRAP_T: GLenum = 0x2803;
const GL_CLAMP_TO_EDGE: GLint = 0x812F;
const GL_BLEND: GLenum = 0x0BE2;
const GL_SRC_ALPHA: GLenum = 0x0302;
const GL_ONE_MINUS_SRC_ALPHA: GLenum = 0x0303;
const GL_UNPACK_ALIGNMENT: GLenum = 0x0CF5;
const GL_NEAREST: GLint = 0x2600;
const GL_TEXTURE1: GLenum = 0x84C1;
const GL_TEXTURE2: GLenum = 0x84C2;

/// One vertex of a quad. Position in screen pixels, colour 0..1, atlas UV
/// (glyph mode), and the rounded-rect SDF inputs (local offset from the
/// rect centre, the rect half-extent, the corner radius) — plus a mode
/// selector. extern layout so the field order IS the glVertexAttribPointer
/// offset table. HOT — six per quad, thousands per frame → A7.
///
/// A3 exception: the `[]Vertex` buffer is array-of-structs, not SoA — a GL
/// vertex buffer must be INTERLEAVED so one glVertexAttribPointer stride
/// reads each attribute; SoA would need a separate buffer + bind per
/// attribute. The interleaved layout is the GPU's contract, recorded here.
const Vertex = extern struct {
    x: f32,
    y: f32,
    r: f32,
    g: f32,
    b: f32,
    a: f32,
    u: f32,
    v: f32,
    lx: f32,
    ly: f32,
    hx: f32,
    hy: f32,
    rad: f32,
    mode: f32,

    comptime {
        // Budget: 14 × f32 = 56 bytes, exact (extern, no padding). Raising
        // this requires an A7.1 justification here.
        std.debug.assert(@sizeOf(Vertex) == 56);
    }
};

const mode_rrect: f32 = 0; // rounded rect: SDF coverage
const mode_glyph: f32 = 1; // glyph: atlas .r coverage
const mode_solid: f32 = 2; // solid fill: full coverage (sharp rects, lines)

const vert_src: [:0]const GLchar =
    \\attribute vec2 aPos;
    \\attribute vec4 aColor;
    \\attribute vec2 aUV;
    \\attribute vec2 aLocal;
    \\attribute vec2 aHalf;
    \\attribute float aRadius;
    \\attribute float aMode;
    \\uniform vec2 uViewport;
    \\varying vec4 vColor;
    \\varying vec2 vUV;
    \\varying vec2 vLocal;
    \\varying vec2 vHalf;
    \\varying float vRadius;
    \\varying float vMode;
    \\void main() {
    \\  vColor = aColor; vUV = aUV; vLocal = aLocal; vHalf = aHalf;
    \\  vRadius = aRadius; vMode = aMode;
    \\  vec2 clip = vec2(aPos.x / uViewport.x * 2.0 - 1.0,
    \\                   1.0 - aPos.y / uViewport.y * 2.0);
    \\  gl_Position = vec4(clip, 0.0, 1.0);
    \\}
;

const frag_src: [:0]const GLchar =
    \\precision mediump float;
    \\uniform sampler2D uAtlas;
    \\varying vec4 vColor;
    \\varying vec2 vUV;
    \\varying vec2 vLocal;
    \\varying vec2 vHalf;
    \\varying float vRadius;
    \\varying float vMode;
    \\void main() {
    \\  float cov = 1.0;
    \\  if (vMode < 0.5) {
    \\    vec2 d = abs(vLocal) - (vHalf - vec2(vRadius));
    \\    float dist = length(max(d, 0.0)) - vRadius;
    \\    cov = clamp(0.5 - dist, 0.0, 1.0);
    \\  } else if (vMode < 1.5) {
    \\    cov = texture2D(uAtlas, vUV).r;
    \\  }
    \\  gl_FragColor = vec4(vColor.rgb, vColor.a * cov);
    \\}
;

/// The GPU renderer: a compiled program, one dynamic vertex buffer, one
/// atlas texture, and the cached uniform/attribute locations. A7.2: cold
/// struct, size guard waived — exactly one per window; its hot data is the
/// vertex buffer and the texture, both GPU-side.
pub const Renderer = struct {
    program: GLuint,
    vbo: GLuint,
    atlas_tex: GLuint,
    atlas_dim: u32,
    u_viewport: GLint,
    u_atlas: GLint,
    a_pos: GLint,
    a_color: GLint,
    a_uv: GLint,
    a_local: GLint,
    a_half: GLint,
    a_radius: GLint,
    a_mode: GLint,
};

fn compileShader(kind: GLenum, src: [:0]const GLchar) Error!GLuint {
    const sh = glCreateShader(kind);
    var ptr: [*:0]const GLchar = src.ptr;
    glShaderSource(sh, 1, @ptrCast(&ptr), null);
    glCompileShader(sh);
    var ok: GLint = 0;
    glGetShaderiv(sh, GL_COMPILE_STATUS, &ok);
    if (ok == 0) {
        var log: [1024]GLchar = undefined;
        var n: GLsizei = 0;
        glGetShaderInfoLog(sh, log.len, &n, &log);
        elog("shader compile FAILED: {s}", .{log[0..@intCast(n)]});
        return Error.GpuInit;
    }
    return sh;
}

/// Build the program, the vertex buffer, and the atlas texture object.
/// Call once after the context is current.
pub fn initRenderer() Error!Renderer {
    const vs = try compileShader(GL_VERTEX_SHADER, vert_src);
    const fs = try compileShader(GL_FRAGMENT_SHADER, frag_src);
    const prog = glCreateProgram();
    glAttachShader(prog, vs);
    glAttachShader(prog, fs);
    glLinkProgram(prog);
    var ok: GLint = 0;
    glGetProgramiv(prog, GL_LINK_STATUS, &ok);
    if (ok == 0) {
        var log: [1024]GLchar = undefined;
        var n: GLsizei = 0;
        glGetProgramInfoLog(prog, log.len, &n, &log);
        elog("program link FAILED: {s}", .{log[0..@intCast(n)]});
        return Error.GpuInit;
    }

    var vbo: GLuint = 0;
    glGenBuffers(1, @ptrCast(&vbo));
    var tex: GLuint = 0;
    glGenTextures(1, @ptrCast(&tex));

    elog("renderer ready (program linked, atlas texture + vbo created)", .{});
    return .{
        .program = prog,
        .vbo = vbo,
        .atlas_tex = tex,
        .atlas_dim = 0,
        .u_viewport = glGetUniformLocation(prog, "uViewport"),
        .u_atlas = glGetUniformLocation(prog, "uAtlas"),
        .a_pos = glGetAttribLocation(prog, "aPos"),
        .a_color = glGetAttribLocation(prog, "aColor"),
        .a_uv = glGetAttribLocation(prog, "aUV"),
        .a_local = glGetAttribLocation(prog, "aLocal"),
        .a_half = glGetAttribLocation(prog, "aHalf"),
        .a_radius = glGetAttribLocation(prog, "aRadius"),
        .a_mode = glGetAttribLocation(prog, "aMode"),
    };
}

/// (Re)upload the atlas bitmap to the texture when it has changed. The
/// shell calls this after building vertices (which is what fills the atlas).
pub fn uploadAtlas(r: *Renderer, atlas: *atlas_mod.Atlas) void {
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, r.atlas_tex);
    if (atlas.dirty or r.atlas_dim != atlas.dim) {
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        glTexImage2D(GL_TEXTURE_2D, 0, @intCast(GL_LUMINANCE), @intCast(atlas.dim), @intCast(atlas.dim), 0, GL_LUMINANCE, GL_UNSIGNED_BYTE, atlas.bitmap.ptr);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        r.atlas_dim = atlas.dim;
        atlas.dirty = false;
    }
}

fn argb(c: u32) [4]f32 {
    return .{
        @as(f32, @floatFromInt((c >> 16) & 0xFF)) / 255.0,
        @as(f32, @floatFromInt((c >> 8) & 0xFF)) / 255.0,
        @as(f32, @floatFromInt(c & 0xFF)) / 255.0,
        @as(f32, @floatFromInt((c >> 24) & 0xFF)) / 255.0,
    };
}

/// One quad → six vertices (two triangles: 0-1-2, 0-2-3). Corners are
/// given clockwise from top-left in screen px; per-corner uv and local
/// offset; per-quad half-extent, radius, mode, colour.
fn pushQuad(
    verts: *std.ArrayListUnmanaged(Vertex),
    gpa: std.mem.Allocator,
    p: [4][2]f32,
    uv: [4][2]f32,
    local: [4][2]f32,
    half: [2]f32,
    rad: f32,
    mode: f32,
    col: [4]f32,
) error{OutOfMemory}!void {
    const corner = struct {
        fn v(pp: [2]f32, tt: [2]f32, ll: [2]f32, hh: [2]f32, rr: f32, mm: f32, cc: [4]f32) Vertex {
            return .{
                .x = pp[0],   .y = pp[1],
                .r = cc[0],   .g = cc[1],   .b = cc[2],   .a = cc[3],
                .u = tt[0],   .v = tt[1],
                .lx = ll[0],  .ly = ll[1],
                .hx = hh[0],  .hy = hh[1],
                .rad = rr,    .mode = mm,
            };
        }
    }.v;
    const order = [6]usize{ 0, 1, 2, 0, 2, 3 };
    for (order) |i| {
        try verts.append(gpa, corner(p[i], uv[i], local[i], half, rad, mode, col));
    }
}

const zero_uv = [4][2]f32{ .{ 0, 0 }, .{ 0, 0 }, .{ 0, 0 }, .{ 0, 0 } };
const zero_local = [4][2]f32{ .{ 0, 0 }, .{ 0, 0 }, .{ 0, 0 }, .{ 0, 0 } };

/// Translate a draw list into the vertex buffer, filling the atlas with any
/// glyphs not yet present. Returns the owned vertex slice (caller frees).
/// The same item order as raster.paint → the same back-to-front z-order.
pub fn buildVertices(
    gpa: std.mem.Allocator,
    engine: *text.Engine,
    atlas: *atlas_mod.Atlas,
    list: raster.DrawList.Slice,
    scale: f32,
) atlas_mod.Error!std.ArrayListUnmanaged(Vertex) {
    var verts: std.ArrayListUnmanaged(Vertex) = .empty;
    errdefer verts.deinit(gpa);
    const inv: f32 = if (atlas.dim == 0) 0 else 1.0 / @as(f32, @floatFromInt(atlas.dim));

    // DPI / UI scale: the layout is produced at LOGICAL size; here every
    // position and size is multiplied by `scale`, and glyphs are rasterized at
    // px*scale, so the feed lands at physical size and stays crisp (not an
    // upscaled blur). The design was authored at ~2×; this is that 2×.
    const tags = list.items(.tags);
    const data = list.items(.data);
    for (tags, data) |tag, bare| switch (tag) {
        .rect => {
            const it = bare.rect;
            if (it.w == 0 or it.h == 0) continue;
            const x: f32 = @as(f32, @floatFromInt(it.x)) * scale;
            const y: f32 = @as(f32, @floatFromInt(it.y)) * scale;
            const w: f32 = @as(f32, @floatFromInt(it.w)) * scale;
            const h: f32 = @as(f32, @floatFromInt(it.h)) * scale;
            const rad: f32 = @min(@as(f32, @floatFromInt(it.radius)) * scale, @min(w, h) / 2.0);
            const p = [4][2]f32{ .{ x, y }, .{ x + w, y }, .{ x + w, y + h }, .{ x, y + h } };
            if (rad > 0) {
                const hw = w / 2.0;
                const hh = h / 2.0;
                const local = [4][2]f32{ .{ -hw, -hh }, .{ hw, -hh }, .{ hw, hh }, .{ -hw, hh } };
                try pushQuad(&verts, gpa, p, zero_uv, local, .{ hw, hh }, rad, mode_rrect, argb(it.color));
            } else {
                try pushQuad(&verts, gpa, p, zero_uv, zero_local, .{ 0, 0 }, 0, mode_solid, argb(it.color));
            }
        },
        .line => {
            const it = bare.line;
            const x0: f32 = @as(f32, @floatFromInt(it.x0)) * scale;
            const y0: f32 = @as(f32, @floatFromInt(it.y0)) * scale;
            const x1: f32 = @as(f32, @floatFromInt(it.x1)) * scale;
            const y1: f32 = @as(f32, @floatFromInt(it.y1)) * scale;
            var dx = x1 - x0;
            var dy = y1 - y0;
            const len = @sqrt(dx * dx + dy * dy);
            if (len < 0.0001) {
                dx = 1;
                dy = 0;
            } else {
                dx /= len;
                dy /= len;
            }
            // Square pen: half-thickness across, and extend half past each
            // end to match the rasterizer's square cap.
            const t: f32 = @as(f32, @floatFromInt(@max(@as(u8, 1), it.thickness))) * scale;
            const hth = t / 2.0;
            const nx = -dy * hth; // normal × half-thickness
            const ny = dx * hth;
            const ex = dx * hth; // along × half (cap extension)
            const ey = dy * hth;
            const ax = x0 - ex;
            const ay = y0 - ey;
            const bx = x1 + ex;
            const by = y1 + ey;
            const p = [4][2]f32{
                .{ ax + nx, ay + ny },
                .{ bx + nx, by + ny },
                .{ bx - nx, by - ny },
                .{ ax - nx, ay - ny },
            };
            try pushQuad(&verts, gpa, p, zero_uv, zero_local, .{ 0, 0 }, 0, mode_solid, argb(it.color));
        },
        .text => {
            const it = bare.text;
            const px_scaled: u32 = @intFromFloat(@round(@as(f32, @floatFromInt(it.px)) * scale));
            const gl = try atlas_mod.ensure(gpa, engine, atlas, @enumFromInt(it.weight), it.codepoint, px_scaled);
            if (gl.w == 0 or gl.h == 0) continue;
            // position scaled; the glyph is already physical (rasterized at px*scale)
            const dx: f32 = @as(f32, @floatFromInt(it.x)) * scale + @as(f32, @floatFromInt(gl.bear_x));
            const dy: f32 = @as(f32, @floatFromInt(it.baseline)) * scale + @as(f32, @floatFromInt(gl.bear_y));
            const w: f32 = @floatFromInt(gl.w);
            const h: f32 = @floatFromInt(gl.h);
            const ua: f32 = @as(f32, @floatFromInt(gl.x)) * inv;
            const va: f32 = @as(f32, @floatFromInt(gl.y)) * inv;
            const ub: f32 = @as(f32, @floatFromInt(gl.x + gl.w)) * inv;
            const vb: f32 = @as(f32, @floatFromInt(gl.y + gl.h)) * inv;
            const p = [4][2]f32{ .{ dx, dy }, .{ dx + w, dy }, .{ dx + w, dy + h }, .{ dx, dy + h } };
            const uv = [4][2]f32{ .{ ua, va }, .{ ub, va }, .{ ub, vb }, .{ ua, vb } };
            try pushQuad(&verts, gpa, p, uv, zero_local, .{ 0, 0 }, 0, mode_glyph, argb(it.color));
        },
        .cell => {}, // the embedded-strike fallback path is not used by the feed/field
    };
    return verts;
}

/// Upload the vertex buffer and issue the single draw call. `atlas` must
/// already be uploaded (uploadAtlas) and bound on texture unit 0.
pub fn draw(r: *Renderer, verts: []const Vertex, vw: i32, vh: i32) void {
    if (verts.len == 0) return;
    glUseProgram(r.program);
    glBindBuffer(GL_ARRAY_BUFFER, r.vbo);
    glBufferData(GL_ARRAY_BUFFER, @intCast(verts.len * @sizeOf(Vertex)), verts.ptr, GL_DYNAMIC_DRAW);

    const stride: GLsizei = @sizeOf(Vertex);
    bindAttrib(r.a_pos, 2, stride, 0);
    bindAttrib(r.a_color, 4, stride, 8);
    bindAttrib(r.a_uv, 2, stride, 24);
    bindAttrib(r.a_local, 2, stride, 32);
    bindAttrib(r.a_half, 2, stride, 40);
    bindAttrib(r.a_radius, 1, stride, 48);
    bindAttrib(r.a_mode, 1, stride, 52);

    // Bind the glyph atlas on unit 0 HERE every frame: the field pass binds
    // its own ramp texture to the same unit, so the feed must reclaim it or
    // it samples the ramp instead and all text vanishes.
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, r.atlas_tex);
    glUniform2f(r.u_viewport, @floatFromInt(vw), @floatFromInt(vh));
    glUniform1i(r.u_atlas, 0);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glDrawArrays(GL_TRIANGLES, 0, @intCast(verts.len));
}

/// The feed render path as ONE handle (D3: the vertex layout — `Vertex` is
/// private — stays inside this module, so a caller in another module can hold
/// the path without naming it). The renderer program + atlas texture are built
/// once; `verts` are rebuilt only when the draw list changes (timeline / scroll
/// / resize), never per frame. A7.2: cold struct, size guard waived — one per
/// window; its hot data is the vertex list and the GPU-side buffers/texture.
pub const Feed = struct {
    renderer: Renderer,
    atlas: atlas_mod.Atlas,
    verts: std.ArrayListUnmanaged(Vertex),
};

/// initFeed / feedBuild can fail on GL bring-up (GpuInit) or atlas packing
/// (AtlasFull / OutOfMemory).
pub const FeedError = Error || atlas_mod.Error;

/// Build the feed renderer + an empty atlas. Call once, after the context is
/// current. Atlas dim 2048 matches the preview's proven budget.
pub fn initFeed(gpa: std.mem.Allocator) FeedError!Feed {
    const renderer = try initRenderer();
    var atlas: atlas_mod.Atlas = .{};
    try atlas_mod.init(gpa, &atlas, 2048);
    return .{ .renderer = renderer, .atlas = atlas, .verts = .empty };
}

/// Rebuild the feed vertices from `list` at `scale`, then re-upload the atlas
/// (buildVertices may have packed new glyphs that must reach the texture).
/// New buffer built BEFORE the old is freed, so a failed pack leaves the prior
/// verts intact (E2/C5). Call on change only — see the struct doc.
pub fn feedBuild(
    self: *Feed,
    gpa: std.mem.Allocator,
    engine: *text.Engine,
    list: raster.DrawList.Slice,
    scale: f32,
) atlas_mod.Error!void {
    const fresh = try buildVertices(gpa, engine, &self.atlas, list, scale);
    self.verts.deinit(gpa);
    self.verts = fresh;
    uploadAtlas(&self.renderer, &self.atlas);
}

/// Issue the feed's single draw call (atlas already uploaded by feedBuild).
pub fn feedDraw(self: *Feed, vw: i32, vh: i32) void {
    draw(&self.renderer, self.verts.items, vw, vh);
}

/// Free the CPU-side vertex list + atlas. The GL program/buffer/texture are
/// process-lifetime objects (matching Renderer/FieldRenderer/FieldGrid, none
/// of which deinit) and are reclaimed at exit.
pub fn feedDeinit(self: *Feed, gpa: std.mem.Allocator) void {
    self.verts.deinit(gpa);
    atlas_mod.deinit(gpa, &self.atlas);
}

fn bindAttrib(loc: GLint, size: GLint, stride: GLsizei, byte_off: usize) void {
    if (loc < 0) return;
    const l: GLuint = @intCast(loc);
    glEnableVertexAttribArray(l);
    glVertexAttribPointer(l, size, GL_FLOAT, 0, stride, @ptrFromInt(byte_off));
}

/// One-line glGetError probe for the diagnostic trail.
pub fn glError(comptime step: []const u8) void {
    const e = glGetErrorGL();
    if (e != 0) elog("{s}: glGetError = 0x{x}", .{ step, e });
}

// ===========================================================================
// THE FIELD RAMP: the ASCII density ramp (field.ambient_ramp_rich) rasterized
// ONCE into a single horizontal strip texture, lightest→densest. The sprite
// field (below) samples a glyph out of this strip per symbol. Built on the CPU
// from the font engine, uploaded to one GL texture, never touched again.
// ===========================================================================

/// The field's ramp-strip texture + its metrics. A7.2: cold struct, size
/// guard waived — one per window; its hot data is the GPU texture.
pub const FieldRenderer = struct {
    ramp_tex: GLuint,
    ramp_n: u32,
    cell_w: f32,
    cell_h: f32,
};

/// Rasterize field.ambient_ramp_rich at the cell height — one glyph per
/// cell_w-wide slot, baseline at 0.78·cell_h — into one LUMINANCE strip
/// texture the sprite field samples.
pub fn initFieldRenderer(
    gpa: std.mem.Allocator,
    engine: *text.Engine,
    cell_w: u16,
    cell_h: u16,
) (Error || error{OutOfMemory})!FieldRenderer {
    // Ramp strip: N glyphs, each cell_w wide, cell_h tall, rasterized at the
    // cell height and laid out left to right (lightest→densest).
    const ramp = field.ambient_ramp_rich;
    const n_glyphs: u32 = ramp.len;
    const sw: u32 = cell_w;
    const sh: u32 = cell_h;
    const strip_w: u32 = n_glyphs * sw;
    const strip = try gpa.alloc(u8, strip_w * sh);
    defer gpa.free(strip);
    @memset(strip, 0);
    const baseline: i32 = @intCast((@as(u32, cell_h) * 78) / 100);
    for (ramp, 0..) |ch, i| {
        const g = try text.glyph(gpa, engine, .regular, ch, cell_h);
        if (g.w == 0 or g.h == 0) continue;
        const slot_x0: i32 = @as(i32, @intCast(i * sw)) + g.bear_x;
        const y0: i32 = baseline + g.bear_y;
        var row: i32 = 0;
        while (row < g.h) : (row += 1) {
            const dy = y0 + row;
            if (dy < 0 or dy >= sh) continue;
            var col: i32 = 0;
            while (col < g.w) : (col += 1) {
                const dx = slot_x0 + col;
                // keep the glyph within ITS slot so neighbours never bleed
                if (dx < @as(i32, @intCast(i * sw)) or dx >= @as(i32, @intCast((i + 1) * sw))) continue;
                const a = g.alpha[@as(usize, @intCast(row)) * g.w + @as(usize, @intCast(col))];
                if (a == 0) continue;
                strip[@as(usize, @intCast(dy)) * strip_w + @as(usize, @intCast(dx))] = a;
            }
        }
    }

    var tex: GLuint = 0;
    glGenTextures(1, @ptrCast(&tex));
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, @intCast(GL_LUMINANCE), @intCast(strip_w), @intCast(sh), 0, GL_LUMINANCE, GL_UNSIGNED_BYTE, strip.ptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    elog("field ramp ready ({d} glyphs, cell {d}x{d})", .{ n_glyphs, cell_w, cell_h });
    return .{
        .ramp_tex = tex,
        .ramp_n = n_glyphs,
        .cell_w = @floatFromInt(cell_w),
        .cell_h = @floatFromInt(cell_h),
    };
}

// ===========================================================================
// THE FIELD GRID RENDERER (the committed direction): render the PURE CPU
// simulation (core/glyph_field.zig) grid-intensity, the mockup's look. Each
// frame the shell uploads the field's `height` to a single R32F texture; this
// full-screen pass samples it PER CELL, maps |height|·gain through the light
// gate and the glyph ramp, and draws one discrete glyph per cell. Because the
// field is a smooth medium, neighbours share a glyph → symbols GROUP into the
// lines/shapes the mockup has, and they change together as the field evolves.
// The physics is the testable CPU core; this is just the (thin) render of it.
// ===========================================================================

const field_grid_vert_src: [:0]const GLchar =
    \\attribute vec2 aPos;
    \\void main() { gl_Position = vec4(aPos, 0.0, 1.0); }
;

const field_grid_frag_src: [:0]const GLchar =
    \\precision highp float;
    \\uniform vec2 uViewport;
    \\uniform float uTime;
    \\uniform vec2 uCell;       // cell width,height in px
    \\uniform float uRampN;
    \\uniform sampler2D uRamp;
    \\uniform sampler2D uField;  // R32F height, cols×rows (one texel per cell)
    \\uniform vec2 uFieldSize;   // cols, rows
    \\uniform float uGain;       // |height| → intensity scale (look knob)
    \\uniform vec2 uMouse;       // cursor in cells (x<0 ⇒ no cursor)
    \\uniform sampler2D uDye;    // R32F persistent colour charge, cols×rows
    \\void main() {
    \\  vec2 px = vec2(gl_FragCoord.x, uViewport.y - gl_FragCoord.y); // top-down
    \\  vec2 cell = floor(px / uCell);
    \\  // sample THIS cell's height from the simulation (nearest, 1 texel/cell)
    \\  float h = texture2D(uField, (cell + 0.5) / uFieldSize).r;
    \\  float intensity = abs(h) * uGain;
    \\  // orbiting light gate (cell units) — the mockup's soul; most of the
    \\  // screen is quiet, a soft moving light reveals the field.
    \\  float cols = uViewport.x / uCell.x;
    \\  float rows = uViewport.y / uCell.y;
    \\  float lx = cols * 0.5 + cols * 0.18 * sin(uTime * 0.05);
    \\  float ly = rows * 0.28 + rows * 0.10 * sin(uTime * 0.07 + 1.0);
    \\  float pool = max(0.0, 1.0 - distance(cell + 0.5, vec2(lx, ly)) / (cols * 0.85));
    \\  // CURSOR LIGHT: a soft, brighter halo follows the pointer and reveals
    \\  // the field around it — the field's own light mechanic, localized to you.
    \\  float cg = (uMouse.x >= 0.0) ? 0.55 * max(0.0, 1.0 - distance(cell + 0.5, uMouse) / 9.0) : 0.0;
    \\  float b = 0.38 + 0.55 * pool + cg;
    \\  // persistent colour charge from effects (a like stains it red)
    \\  float dye = clamp(texture2D(uDye, (cell + 0.5) / uFieldSize).r, 0.0, 1.0);
    \\  float dn = clamp(intensity * min(1.2, b), 0.0, 1.0);
    \\  dn = max(dn, dye * 0.7);                 // red charge keeps its glyphs lit
    \\  if (dn < 0.04) discard;                 // the mockup's sparse cull
    \\  float idx = floor(dn * (uRampN - 1.0) + 0.5);
    \\  vec2 local = fract(px / uCell);
    \\  vec2 ruv = vec2((idx + local.x) / uRampN, local.y);
    \\  float cov = texture2D(uRamp, ruv).r;
    \\  // cool grey-white, dimmer; tinting to the rose 'like' colour where dyed.
    \\  float lum = clamp(0.35 + b * 0.45 + intensity * 0.30, 0.0, 1.05);
    \\  vec3 base = mix(vec3(84.0, 89.0, 102.0) / 255.0, vec3(166.0, 172.0, 186.0) / 255.0, clamp(0.28 + b * 0.5, 0.0, 1.0));
    \\  vec3 col = mix(base, vec3(240.0, 97.0, 122.0) / 255.0, dye);
    \\  lum = max(lum, dye * 0.95);             // red reads even in quiet areas
    \\  gl_FragColor = vec4(col * lum, cov);
    \\}
;

/// The grid-intensity field renderer: a program, a full-screen triangle, and
/// the R32F texture the CPU field's height is uploaded into. A7.2: cold struct,
/// size guard waived — one per window; its hot data is the GPU texture.
pub const FieldGrid = struct {
    program: GLuint,
    vbo: GLuint,
    field_tex: GLuint,
    dye_tex: GLuint,
    field_w: u32,
    field_h: u32,
    gain: f32,
    a_pos: GLint,
    u_viewport: GLint,
    u_time: GLint,
    u_cell: GLint,
    u_rampn: GLint,
    u_ramp: GLint,
    u_field: GLint,
    u_fieldsize: GLint,
    u_gain: GLint,
    u_mouse: GLint,
    u_dye: GLint,
};

pub fn initFieldGrid() Error!FieldGrid {
    const vs = try compileShader(GL_VERTEX_SHADER, field_grid_vert_src);
    const fs = try compileShader(GL_FRAGMENT_SHADER, field_grid_frag_src);
    const prog = glCreateProgram();
    glAttachShader(prog, vs);
    glAttachShader(prog, fs);
    glLinkProgram(prog);
    var ok: GLint = 0;
    glGetProgramiv(prog, GL_LINK_STATUS, &ok);
    if (ok == 0) {
        var log: [1024]GLchar = undefined;
        var n: GLsizei = 0;
        glGetProgramInfoLog(prog, log.len, &n, &log);
        elog("field-grid program link FAILED: {s}", .{log[0..@intCast(n)]});
        return Error.GpuInit;
    }
    const tri = [_]f32{ -1, -1, 3, -1, -1, 3 };
    var vbo: GLuint = 0;
    glGenBuffers(1, @ptrCast(&vbo));
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glBufferData(GL_ARRAY_BUFFER, @intCast(tri.len * @sizeOf(f32)), &tri, GL_STATIC_DRAW);

    var tex: GLuint = 0;
    glGenTextures(1, @ptrCast(&tex));
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST_FILTER);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST_FILTER);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    var dtex: GLuint = 0;
    glGenTextures(1, @ptrCast(&dtex));
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, dtex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST_FILTER);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST_FILTER);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    elog("field-grid renderer ready (grid-intensity, R32F height + dye textures)", .{});
    return .{
        .program = prog,
        .vbo = vbo,
        .field_tex = tex,
        .dye_tex = dtex,
        .field_w = 0,
        .field_h = 0,
        .gain = 0.9,
        .a_pos = glGetAttribLocation(prog, "aPos"),
        .u_viewport = glGetUniformLocation(prog, "uViewport"),
        .u_time = glGetUniformLocation(prog, "uTime"),
        .u_cell = glGetUniformLocation(prog, "uCell"),
        .u_rampn = glGetUniformLocation(prog, "uRampN"),
        .u_ramp = glGetUniformLocation(prog, "uRamp"),
        .u_field = glGetUniformLocation(prog, "uField"),
        .u_fieldsize = glGetUniformLocation(prog, "uFieldSize"),
        .u_gain = glGetUniformLocation(prog, "uGain"),
        .u_mouse = glGetUniformLocation(prog, "uMouse"),
        .u_dye = glGetUniformLocation(prog, "uDye"),
    };
}

/// Upload the CPU field's height (len == cols*rows) into the R32F texture.
/// Re-specifies each frame (trivial at field-grid sizes); the texture params
/// set at init persist.
pub fn uploadField(fg: *FieldGrid, height: []const f32, dye: []const f32, cols: u32, rows: u32) void {
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, fg.field_tex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R32F, @intCast(cols), @intCast(rows), 0, GL_RED, GL_FLOAT, height.ptr);
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, fg.dye_tex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R32F, @intCast(cols), @intCast(rows), 0, GL_RED, GL_FLOAT, dye.ptr);
    fg.field_w = cols;
    fg.field_h = rows;
}

/// Draw the field grid-intensity. `fr` supplies the ramp texture + cell metrics
/// (built by initFieldRenderer); `uploadField` must have run this frame.
/// `mx`,`my` are the cursor in cells (top-down); pass mx<0 for no cursor.
pub fn drawFieldGrid(fg: *FieldGrid, fr: *FieldRenderer, mx: f32, my: f32, time: f32, vw: i32, vh: i32) void {
    glUseProgram(fg.program);
    glBindBuffer(GL_ARRAY_BUFFER, fg.vbo);
    bindAttrib(fg.a_pos, 2, 2 * @sizeOf(f32), 0);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, fr.ramp_tex);
    glUniform1i(fg.u_ramp, 0);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, fg.field_tex);
    glUniform1i(fg.u_field, 1);
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, fg.dye_tex);
    glUniform1i(fg.u_dye, 2);
    glUniform2f(fg.u_viewport, @floatFromInt(vw), @floatFromInt(vh));
    glUniform1f(fg.u_time, time);
    glUniform2f(fg.u_cell, fr.cell_w, fr.cell_h);
    glUniform1f(fg.u_rampn, @floatFromInt(fr.ramp_n));
    glUniform2f(fg.u_fieldsize, @floatFromInt(fg.field_w), @floatFromInt(fg.field_h));
    glUniform1f(fg.u_gain, fg.gain);
    glUniform2f(fg.u_mouse, mx, my);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glDrawArrays(GL_TRIANGLES, 0, 3);
}
