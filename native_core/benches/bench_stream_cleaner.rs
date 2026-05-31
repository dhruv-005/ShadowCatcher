// ============================================
// SHADOW CATCHER - Stream Cleaner Benchmarks
// ============================================

use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BenchmarkId, Throughput,
};
use shadow_core::stream::{
    StreamSegment,
    packet_filter::PacketFilter,
};

// ─────────────────────────────────────────
// TEST DATA
// ─────────────────────────────────────────

fn clean_segment(size: usize) -> Vec<u8> {
    vec![0xABu8; size]
}

fn segment_with_pe(size: usize) -> Vec<u8> {
    let mut data = vec![0xABu8; size / 2];
    data.extend_from_slice(b"MZ\x90\x00");
    data.extend_from_slice(&vec![0xABu8; size / 2 - 4]);
    data
}

fn mpegts_segment(packets: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(packets * 188);
    for i in 0..packets {
        let mut packet = vec![0u8; 188];
        packet[0] = 0x47; // Sync byte
        packet[1] = (i >> 8) as u8 & 0x1F;
        packet[2] = (i & 0xFF) as u8;
        packet[3] = 0x10;
        for j in 4..188 {
            packet[j] = (i * j % 256) as u8;
        }
        data.extend_from_slice(&packet);
    }
    data
}

// ─────────────────────────────────────────
// PACKET FILTER BENCHMARKS
// ─────────────────────────────────────────

fn bench_chunk_filtering(c: &mut Criterion) {
    let filter = PacketFilter::new();
    let sizes = [1024, 64 * 1024, 512 * 1024, 1024 * 1024];

    let mut group = c.benchmark_group("chunk_filtering");

    for size in &sizes {
        let data = clean_segment(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("clean_chunk", size),
            &data,
            |b, d| {
                b.iter(|| {
                    black_box(
                        filter.filter_chunk(black_box(d)).unwrap()
                    )
                })
            },
        );
    }
    group.finish();
}

fn bench_segment_filtering(c: &mut Criterion) {
    let filter = PacketFilter::new();

    let sizes = [
        ("1_packet",    188),
        ("10_packets",  1880),
        ("50_packets",  9400),
        ("100_packets", 18800),
    ];

    let mut group = c.benchmark_group("segment_filtering");

    for (name, size) in &sizes {
        let data = clean_segment(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("clean_segment", name),
            &data,
            |b, d| {
                b.iter(|| {
                    let seg = StreamSegment::new(
                        0,
                        "https://example.com/seg.ts".to_string(),
                        5.0,
                        d.clone(),
                    );
                    black_box(
                        filter.filter_segment(black_box(seg)).unwrap()
                    )
                })
            },
        );
    }
    group.finish();
}

fn bench_scan_bytes(c: &mut Criterion) {
    let filter = PacketFilter::new();
    let clean = clean_segment(1024);
    let malicious = segment_with_pe(1024);

    let mut group = c.benchmark_group("scan_bytes");
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("scan_clean", |b| {
        b.iter(|| {
            black_box(filter.scan_bytes(black_box(&clean)))
        })
    });

    group.bench_function("scan_malicious", |b| {
        b.iter(|| {
            black_box(filter.scan_bytes(black_box(&malicious)))
        })
    });

    group.finish();
}

fn bench_mpegts_filtering(c: &mut Criterion) {
    let filter = PacketFilter::new();

    let packet_counts = [10u64, 50, 100, 500];
    let mut group = c.benchmark_group("mpegts_filtering");

    for &count in &packet_counts {
        let data = mpegts_segment(count as usize);
        group.throughput(Throughput::Bytes(count * 188));

        group.bench_with_input(
            BenchmarkId::new("filter_packets", count),
            &data,
            |b, d| {
                b.iter(|| {
                    let seg = StreamSegment::new(
                        0,
                        "https://cdn.example.com/hls/seg.ts".to_string(),
                        5.0,
                        d.clone(),
                    );
                    black_box(
                        filter.filter_segment(black_box(seg)).unwrap()
                    )
                })
            },
        );
    }
    group.finish();
}

fn bench_parallel_segments(c: &mut Criterion) {
    use rayon::prelude::*;

    let filter = std::sync::Arc::new(PacketFilter::new());
    let segment_count = 20;

    let mut group = c.benchmark_group("parallel_segments");
    group.throughput(Throughput::Elements(segment_count as u64));

    group.bench_function("sequential", |b| {
        b.iter(|| {
            for i in 0..segment_count {
                let data = clean_segment(188 * 10);
                let seg = StreamSegment::new(
                    i,
                    format!("https://cdn.example.com/seg{}.ts", i),
                    5.0,
                    data,
                );
                black_box(filter.filter_segment(seg).unwrap());
            }
        })
    });

    group.bench_function("parallel_rayon", |b| {
        b.iter(|| {
            let segments: Vec<_> = (0..segment_count)
                .map(|i| StreamSegment::new(
                    i,
                    format!("https://cdn.example.com/seg{}.ts", i),
                    5.0,
                    clean_segment(188 * 10),
                ))
                .collect();

            segments.into_par_iter()
                .map(|seg| filter.filter_segment(seg).unwrap())
                .collect::<Vec<_>>()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_chunk_filtering,
    bench_segment_filtering,
    bench_scan_bytes,
    bench_mpegts_filtering,
    bench_parallel_segments,
);
criterion_main!(benches);
