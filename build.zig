const std = @import("std");

pub fn build(b: *std.Build) void {
    // ----- Main executable -----
    const exe = b.addExecutable(.{
        .name = "rsa",
        .root_source_file = b.path("src/main.zig"),
        .target = b.host,
    });

    // ----- Install -----
    b.installArtifact(exe);

    // ----- Run -----
    const run_exe = b.addRunArtifact(exe);

    if (b.args) |args| run_exe.addArgs(args); // Add args

    const run_step = b.step("run", "Run the appliction");
    run_step.dependOn(&run_exe.step);
}
