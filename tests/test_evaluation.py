import pytest

from skillupdate.evaluation import classification, grouped_bootstrap, validate_groups
from skillupdate.evaluation.metrics import mcnemar_family_exact, pr_curve


def rows():
    return [
        {
            "base_skill_id": str(i),
            "expected_snapshot_status": y,
            "snapshot_status": p,
            "update_id": str(i),
            "split": "test",
            "source_category": "CONTROLLED_MALICIOUS"
            if y == "MALICIOUS"
            else "BENIGN_UPDATES",
            "scenario": "T1" if y == "MALICIOUS" else "T3",
        }
        for i, (y, p) in enumerate(
            [
                ("MALICIOUS", "MALICIOUS"),
                ("MALICIOUS", "UNKNOWN"),
                ("BENIGN", "MALICIOUS"),
                ("BENIGN", "BENIGN"),
            ]
        )
    ]


def test_abstention_denominators_are_explicit():
    result = classification(rows())
    assert result["coverage"] == 0.75
    assert result["precision"] == 0.5
    assert result["recall"] == 1
    assert result["end_to_end_detection_recall"] == 0.5
    assert result["auprc"] is None


def test_tied_pr_scores_use_group_threshold():
    points, area = pr_curve([1, 0], [0.5, 0.5])
    assert len(points) == 1 and area == 0.5


def test_bootstrap_is_reproducible_and_grouped():
    a = grouped_bootstrap(rows(), iterations=30)
    assert a == grouped_bootstrap(rows(), iterations=30)
    assert a["precision"]["cluster_count"] == 4


def test_family_split_leakage_rejected():
    data = rows()
    data[1]["base_skill_id"] = data[0]["base_skill_id"]
    data[1]["split"] = "train"
    with pytest.raises(ValueError, match="crosses"):
        validate_groups(data)


def test_unverified_adversarial_labels_rejected():
    data = rows()
    data[0]["source_category"] = "ADVERSARIAL"
    with pytest.raises(ValueError, match="independent"):
        validate_groups(data)


def test_mcnemar_groups_skill_events():
    assert mcnemar_family_exact(rows(), rows())["p_value"] == 1
