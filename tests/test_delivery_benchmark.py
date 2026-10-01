import pytest

from benchmarks.delivery import percentile, record_digest, verify_alerts


def test_nearest_rank_delivery_percentiles():
    samples = list(range(1, 101))
    assert percentile(samples, .50) == 50
    assert percentile(samples, .95) == 95
    assert percentile(samples, .99) == 99
    with pytest.raises(ValueError, match='without deliveries'):
        percentile([], .95)


def test_delivery_verification_requires_whole_record_and_sse_id():
    row = {'sequence': 1, 'alert_id': 'alert-1', 'flow_id': 'flow-1',
           'threat_class': 'DDOS', 'supporting_evidence': 'observed packet rate'}
    accepted = {'flow-1': row}
    received = {'flow-1': {'row': row.copy(), 'sse_id': '1', 'latency_ms': 10}}
    stored = {'flow-1': row.copy()}
    verify_alerts(accepted, received, stored, 1)

    received['flow-1']['row']['supporting_evidence'] = 'different evidence'
    with pytest.raises(ValueError, match='data differs'):
        verify_alerts(accepted, received, stored, 1)
    received['flow-1']['row'] = row.copy()

    received['flow-1']['sse_id'] = '2'
    with pytest.raises(ValueError, match='SSE id differs'):
        verify_alerts(accepted, received, stored, 1)
    received['flow-1']['sse_id'] = '1'

    with pytest.raises(ValueError, match='count differs'):
        verify_alerts(accepted, {}, stored, 1)


def test_durable_record_digest_is_order_independent_and_covers_data():
    first = {'sequence': 1, 'alert_id': 'one', 'supporting_evidence': 'a'}
    second = {'sequence': 2, 'alert_id': 'two', 'supporting_evidence': 'b'}
    assert record_digest([first, second]) == record_digest([second, first])
    assert record_digest([first, second]) != record_digest([first, second | {'supporting_evidence': 'changed'}])
