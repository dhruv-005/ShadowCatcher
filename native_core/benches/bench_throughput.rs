// ============================================
// SHADOW CATCHER - Throughput Benchmarks
// ============================================

use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BenchmarkId, Throughput,
};
use shadow_core::stream::output_writer::OutputWriter;
use shadow_core::throttler::tcp_controller::TcpController;

// ─────────────────────────────────────────
// OUTPUT WRITER BENCHMARKS
// ─────────────────────────────────────────

fn bench_output_writer(c: &mut Criterion) {
    let mut group = c.benchmark_group("output_writer");

    let chunk_sizes: &[usize] = &[
        4 * 1024,        // 4KB
        64 * 1024,       // 64KB
        512 * 1024,      // 512KB
        1024 * 1024,     // 1MB
    ];

    for &chunk_size in chunk_sizes {
        let data = vec![0xAAu8; chunk_size];
        group.throughput(Throughput::Bytes(chunk_size as u64));

        group.bench_with_input(
            BenchmarkId::new("write_chunk", chunk_size),
            &data,
            |b, d| {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path()
                    .join("bench_output.mp4")
                    .to_string_lossy()
                    .to_string();

                b.iter(|| {
                    let writer = OutputWriter::new(&path).unwrap();
                    writer.write_bytes(black_box(d)).unwrap();
                    writer.finalize().unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_output_writer_sequential(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path()
        .join("bench_seq.mp4")
        .to_string_lossy()
        .to_string();

    let chunk = vec![0xBBu8; 64 * 1024]; // 64KB chunk
    let chunk_counts = [10u64, 50, 100, 500];

    let mut group = c.benchmark_group("sequential_write");

    for &count in &chunk_counts {
        let total_bytes = count * 64 * 1024;
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("write_chunks", count),
            &count,
            |b, &n| {
                b.iter(|| {
                    let writer = OutputWriter::new(&path).unwrap();
                    for _ in 0..n {
                        writer.write_bytes(black_box(&chunk)).unwrap();
                    }
                    writer.finalize().unwrap();
                })
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────
// TCP CONTROLLER BENCHMARKS
// ─────────────────────────────────────────

fn bench_tcp_controller(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("tcp_controller");

    group.bench_function("unlimited_no_delay_1kb", |b| {
        let ctrl = TcpController::new(0);
        b.iter(|| {
            rt.block_on(async {
                ctrl.apply_delay(black_box(1024)).await;
            })
        })
    });

    group.bench_function("set_speed_multiplier", |b| {
        let ctrl = TcpController::new(1000);
        let mut val = 0.5f32;
        b.iter(|| {
            rt.block_on(async {
                ctrl.set_speed_multiplier(black_box(val)).await;
                val = 1.0 - val;
            })
        })
    });

    group.bench_function("get_allowed_speed", |b| {
        let ctrl = TcpController::new(1000);
        b.iter(|| {
            rt.block_on(async {
                black_box(ctrl.get_allowed_speed_kbps().await)
            })
        })
    });

    group.finish();
}

// ─────────────────────────────────────────
// HASHING BENCHMARKS
// ─────────────────────────────────────────

fn bench_sha256_hashing(c: &mut Criterion) {
    use sha2::{Sha256, Digest};

    let mut group = c.benchmark_group("sha256_hashing");

    let sizes: &[usize] = &[
        1024,
        64 * 1024,
        512 * 1024,
        1024 * 1024,
    ];

    for &size in sizes {
        let data = vec![0xCCu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("hash", size),
            &data,
            |b, d| {
                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.update(black_box(d));
                    black_box(hasher.finalize())
                })
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────
// MEMORY ALLOCATION BENCHMARKS
// ─────────────────────────────────────────

fn bench_vec_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_allocation");

    let sizes: &[usize] = &[
        64 * 1024,
        512 * 1024,
        4 * 1024 * 1024,
    ];

    for &size in sizes {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("allocate_and_fill", size),
            &size,
            |b, &s| {
                b.iter(|| {
                    let v: Vec<u8> = vec![0xAAu8; s];
                    black_box(v)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("with_capacity_fill", size),
            &size,
            |b, &s| {
                b.iter(|| {
                    let mut v = Vec::with_capacity(s);
                    v.extend(std::iter::repeat(0xAAu8).take(s));
                    black_box(v)
                })
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────
// END-TO-END THROUGHPUT
// ─────────────────────────────────────────

fn bench_end_to_end_pipeline(c: &mut Criterion) {
    use shadow_core::stream::packet_filter::PacketFilter;

    let filter = PacketFilter::new();
    let dir = tempfile::tempdir().unwrap();

    let segment_sizes: &[usize] = &[
        188 * 10,
        188 * 50,
        188 * 100,
        188 * 500,
    ];

    let mut group = c.benchmark_group("end_to_end");

    for &size in segment_sizes {
        let data = vec![0xAAu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("filter_and_write", size),
            &data,
            |b, d| {
                let path = dir.path()
                    .join(format!("output_{}.mp4", size))
                    .to_string_lossy()
                    .to_string();

                b.iter(|| {
                    // Filter
                    let filtered = filter
                        .filter_chunk(black_box(d))
                        .unwrap();

                    // Write
                    let writer = OutputWriter::new(&path).unwrap();
                    writer.write_bytes(&filtered).unwrap();
                    writer.finalize().unwrap();

                    black_box(filtered.len())
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_output_writer,
    bench_output_writer_sequential,
    bench_tcp_controller,
    bench_sha256_hashing,
    bench_vec_allocation,
    bench_end_to_end_pipeline,
);
criterion_main!(benches);
