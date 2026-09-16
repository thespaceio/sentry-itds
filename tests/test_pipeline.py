"""End-to-end tests, including the benchmark the README quotes."""


import pytest

from itds.ingest.generator import SyntheticGenerator
from itds.pipeline import Pipeline


@pytest.fixture(scope="module")
def dataset():
    return SyntheticGenerator(n_users=40, days=50, seed=7).generate()


def test_generator_plants_every_scenario(dataset):
    events, identities, labels = dataset
    assert len(events) > 10_000
    assert len(identities) == 40
    assert {"data_hoarder", "departing_exfil", "compromised_account"} <= set(
        labels.values()
    )


def test_pipeline_runs_and_opens_cases(config, dataset):
    events, identities, labels = dataset
    pipeline = Pipeline(config)
    result = pipeline.run(events, identities)

    assert result["total_detections"] > 0
    assert result["ml_fitted"]
    assert result["cases"]


def test_every_case_is_explained(config, dataset):
    events, identities, _ = dataset
    result = Pipeline(config).run(events, identities)
    for case in result["cases"]:
        assert case.summary.strip()
        assert case.top_detections
        for d in case.top_detections:
            assert d.explanation.strip()


def test_cases_are_pseudonymized_by_default(config, dataset):
    events, identities, _ = dataset
    result = Pipeline(config).run(events, identities)
    for case in result["cases"]:
        assert case.pseudonym and case.pseudonym.startswith("EMP-")


def test_all_planted_threats_are_caught(config, dataset):
    """Recall at the alert budget. The system may be imprecise; it must not be
    blind."""
    events, identities, labels = dataset
    pipeline = Pipeline(config)
    result = pipeline.run(events, identities)
    metrics = pipeline.evaluate(result, labels)
    assert metrics["recall_at_budget"] == 1.0


def test_precision_stays_reasonable(config, dataset):
    events, identities, labels = dataset
    pipeline = Pipeline(config)
    result = pipeline.run(events, identities)
    metrics = pipeline.evaluate(result, labels)
    assert metrics["precision_at_budget"] >= 0.4


def test_clean_departing_users_are_not_flagged(config, dataset):
    """A resignation on its own is not a threat and must never open a case."""
    events, identities, labels = dataset
    result = Pipeline(config).run(events, identities)
    flagged = {c.actor_id for c in result["cases"]}

    clean_departers = {
        a
        for a, i in identities.items()
        if i.departure_notice_on is not None and a not in labels
    }
    assert clean_departers, "fixture should include clean departing users"
    assert not (clean_departers & flagged)


def test_empty_input_is_handled(config):
    result = Pipeline(config).run([], {})
    assert result["cases"] == []
    assert result["total_detections"] == 0


def test_results_persist_to_the_store(config, dataset):
    events, identities, _ = dataset
    pipeline = Pipeline(config)
    store = pipeline.attach_store(config.db_path)
    store.upsert_identities(identities.values())
    result = pipeline.run(events, identities)

    open_cases = store.open_cases()
    assert len(open_cases) == len(result["cases"])
    if result["cases"]:
        actor = result["cases"][0].actor_id
        assert store.detections_for(actor)


def test_run_is_deterministic(config, dataset):
    events, identities, _ = dataset
    a = Pipeline(config).run(events, identities)
    b = Pipeline(config).run(events, identities)
    assert [c.actor_id for c in a["cases"]] == [c.actor_id for c in b["cases"]]
    assert [c.risk_score for c in a["cases"]] == [c.risk_score for c in b["cases"]]
