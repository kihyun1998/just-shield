//! 타이포스쿼팅 유사도 (R2의 기반).
//!
//! 비교 기준 목록은 바이너리에 동봉된다 (`data/popular-actions.txt`).
//! 거리는 OSA(제한 다메라우-레벤슈타인) — 인접 글자 맞바꿈(전치)을 1로 센다.
//! 일반 레벤슈타인은 `aquasecurtiy`(전치)를 2로 계산해 놓친다.

const BUNDLED: &str = include_str!("../data/popular-actions.txt");

/// 동봉된 유명 액션 목록 (소문자).
pub fn bundled_popular() -> Vec<String> {
    BUNDLED
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
}

/// `owner_repo`가 목록의 어떤 항목과 "한 글자 차이"면 그 항목을 돌려준다.
/// 정확히 일치하면(짝퉁이 아니라 본체) None.
pub fn similar_popular(owner_repo: &str, popular: &[String]) -> Option<String> {
    let candidate = owner_repo.to_lowercase();
    if popular.contains(&candidate) {
        return None;
    }
    popular
        .iter()
        .find(|p| {
            // 길이 차이가 1을 넘으면 거리도 1을 넘는다 — 빠른 탈락.
            candidate.len().abs_diff(p.len()) <= 1 && osa_distance(&candidate, p) == 1
        })
        .cloned()
}

/// OSA(optimal string alignment) 거리 — 삽입/삭제/치환/인접 전치 각 1.
pub fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut d = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[m][n]
}

#[cfg(test)]
mod tests {
    use super::{bundled_popular, osa_distance, similar_popular};

    #[test]
    fn transposition_counts_as_one() {
        // 일반 레벤슈타인이면 2 — 전치를 1로 세야 TeamPCP식 위장을 잡는다.
        assert_eq!(osa_distance("aquasecurity", "aquasecurtiy"), 1);
        assert_eq!(osa_distance("actions", "actoins"), 1);
        assert_eq!(osa_distance("same", "same"), 0);
        assert_eq!(osa_distance("checkout", "checkov"), 2);
    }

    #[test]
    fn finds_one_edit_neighbors_but_not_exact_or_distant() {
        let popular = bundled_popular();
        assert_eq!(
            similar_popular("aquasecurtiy/trivy-action", &popular).as_deref(),
            Some("aquasecurity/trivy-action")
        );
        assert_eq!(
            similar_popular("actions/checkoutt", &popular).as_deref(),
            Some("actions/checkout")
        );
        // 본체는 짝퉁이 아니다.
        assert_eq!(similar_popular("actions/checkout", &popular), None);
        // 전혀 다른 이름은 침묵.
        assert_eq!(similar_popular("mycorp/deploy-tool", &popular), None);
    }

    #[test]
    fn bundled_list_has_no_internal_one_edit_collisions() {
        // 목록 내부 충돌은 서로를 짝퉁으로 의심하게 만든다 — 갱신 절차의 안전망.
        let popular = bundled_popular();
        for (i, a) in popular.iter().enumerate() {
            for b in popular.iter().skip(i + 1) {
                assert!(osa_distance(a, b) > 1, "목록 내부 충돌: {a} ↔ {b}");
            }
        }
    }
}
