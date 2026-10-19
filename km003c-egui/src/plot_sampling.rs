//! Keep line geometry proportional to the displayed width, preserving spikes.

type Point = [f64; 2];
type IndexedPoint = (usize, Point);

struct Bucket {
    first: IndexedPoint,
    min: IndexedPoint,
    max: IndexedPoint,
    last: IndexedPoint,
}

impl Bucket {
    fn new(point: IndexedPoint) -> Self {
        Self {
            first: point,
            min: point,
            max: point,
            last: point,
        }
    }

    fn push(&mut self, point: IndexedPoint) {
        if point.1[1] < self.min.1[1] {
            self.min = point;
        }
        if point.1[1] > self.max.1[1] {
            self.max = point;
        }
        self.last = point;
    }

    fn append_to(self, output: &mut Vec<Point>) {
        let mut points = [self.first, self.min, self.max, self.last];
        points.sort_unstable_by_key(|point| point.0);
        let mut previous = None;
        for (index, point) in points {
            if previous != Some(index) {
                output.push(point);
                previous = Some(index);
            }
        }
    }
}

/// Keep at most four original points per screen column, in their original order.
/// The input must be ordered by time. Separate buckets outside the viewport retain endpoints and global extrema
/// for autoscaling. Recomputing against the current bounds restores detail when
/// zooming or panning. Recording and export never use this display-only data.
pub fn sample_line(points: impl Iterator<Item = Point>, x_bounds: [f64; 2], columns: usize) -> Vec<Point> {
    let columns = columns.max(1);
    let budget = columns.saturating_add(3).saturating_mul(4);
    let [start, end] = x_bounds;
    if !start.is_finite()
        || !end.is_finite()
        || end <= start
        || points.size_hint().1.is_some_and(|count| count <= budget)
    {
        return points.collect();
    }

    // Anchor buckets to device time, not the scrolling viewport. Quantizing the
    // interval also avoids regrouping every point when axis labels change the
    // plot width by a few pixels. Otherwise a stationary signal appears to
    // shimmer as different extrema are selected on each frame.
    let interval = ((end - start) / columns as f64).log2().ceil().exp2();
    let mut output = Vec::with_capacity(budget);
    let mut current: Option<(u64, Bucket)> = None;
    for (index, point) in points.enumerate() {
        let column = if point[0] < start {
            0
        } else if point[0] >= end {
            u64::MAX
        } else {
            1 + (point[0] / interval).floor() as u64
        };
        match &mut current {
            Some((previous_column, bucket)) if *previous_column == column => bucket.push((index, point)),
            _ => {
                if let Some((_, bucket)) = current.take() {
                    bucket.append_to(&mut output);
                }
                current = Some((column, Bucket::new((index, point))));
            }
        }
    }
    if let Some((_, bucket)) = current {
        bucket.append_to(&mut output);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_line_keeps_signed_spikes_endpoints_and_time_order() {
        let mut input: Vec<_> = (0..10_000).map(|i| [i as f64, 0.0]).collect();
        input[125][1] = 200.0;
        input[126][1] = -300.0;
        let output = sample_line(input.iter().copied(), [0.0, 10_000.0], 100);
        assert!(output.len() <= 408);
        assert_eq!(output.first(), input.first());
        assert_eq!(output.last(), input.last());
        assert!(output.contains(&input[125]));
        assert!(output.contains(&input[126]));
        assert!(output.windows(2).all(|pair| pair[0][0] < pair[1][0]));
    }

    #[test]
    fn zoom_restores_visible_samples_and_retains_offscreen_extrema() {
        let mut input: Vec<_> = (0..10_000).map(|i| [i as f64, (i % 7) as f64]).collect();
        input[100][1] = -100.0;
        input[9000][1] = 200.0;
        let output = sample_line(input.iter().copied(), [5000.0, 5010.0], 100);
        for point in &input[5000..5010] {
            assert!(output.contains(point));
        }
        assert!(output.contains(&input[100]));
        assert!(output.contains(&input[9000]));
        assert_eq!(output.first(), input.first());
        assert_eq!(output.last(), input.last());
    }

    #[test]
    fn sparse_line_is_unchanged() {
        let input = [[0.0, -1.0], [1.0, 2.0], [2.0, 0.0]];
        assert_eq!(sample_line(input.into_iter(), [0.0, 2.0], 100), input);
        assert!(sample_line(std::iter::empty(), [0.0, 1.0], 0).is_empty());
    }

    #[test]
    fn scrolling_keeps_the_same_interior_extrema() {
        let input: Vec<_> = (0..2000).map(|i| [i as f64, (i % 17) as f64]).collect();
        let before = sample_line(input.iter().copied(), [0.0, 1000.0], 10);
        let after = sample_line(input.iter().copied(), [25.0, 1025.0], 10);
        let interior = |points: Vec<Point>| {
            points
                .into_iter()
                .filter(|point| (128.0..896.0).contains(&point[0]))
                .collect::<Vec<_>>()
        };
        assert_eq!(interior(before), interior(after));
    }
}
