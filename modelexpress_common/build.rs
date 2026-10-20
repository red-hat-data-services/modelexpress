// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(
        [
            "proto/health.proto",
            "proto/api.proto",
            "proto/model.proto",
            "proto/p2p.proto",
            "proto/refit.proto",
        ],
        ["proto"],
    )?;
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
