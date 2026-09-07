from app.catalog import KISA_CATALOG, ImplementationStatus


def test_catalog_has_exactly_49_unique_top_level_weaknesses() -> None:
    assert len(KISA_CATALOG) == 49
    assert [item.number for item in KISA_CATALOG] == list(range(1, 50))
    assert len({item.weakness_id for item in KISA_CATALOG}) == 49
    assert KISA_CATALOG[0].weakness_id == "KISA-2021-01"
    assert KISA_CATALOG[-1].weakness_id == "KISA-2021-49"


def test_catalog_preserves_kisa_source_fields_and_descriptions() -> None:
    sql_injection = KISA_CATALOG[0]
    unsafe_api = KISA_CATALOG[-1]

    assert sql_injection.category == "입력데이터 검증 및 표현"
    assert sql_injection.category_number == 1
    assert sql_injection.name == "SQL 삽입"
    assert sql_injection.description == (
        "SQL 질의문을 생성할 때 검증되지 않은 외부 입력 값을 허용하여 악의적인 "
        "질의문이 실행가능한 보안약점"
    )
    assert sql_injection.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED
    assert unsafe_api.category == "API 오용"
    assert unsafe_api.category_number == 2
    assert unsafe_api.name == "취약한 API 사용"
    assert unsafe_api.description == (
        "취약한 함수를 사용해서 예기치 않은 보안위협에 노출되는 보안약점"
    )
    assert unsafe_api.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED

    assert all(" ".join(item.description.split()) == item.description for item in KISA_CATALOG)
    assert all(" ".join(item.name.split()) == item.name for item in KISA_CATALOG)
    assert all(item.description for item in KISA_CATALOG)
    assert all(
        isinstance(item.implementation_status, ImplementationStatus) for item in KISA_CATALOG
    )


def test_catalog_implementation_status_tracks_actual_rulepack_coverage() -> None:
    manual_review_ids = {
        "KISA-2021-16",
        "KISA-2021-18",
        "KISA-2021-19",
        "KISA-2021-26",
        "KISA-2021-33",
        "KISA-2021-41",
        "KISA-2021-44",
    }
    partially_implemented_ids = {
        f"KISA-2021-{number:02d}"
        for number in range(1, 50)
        if f"KISA-2021-{number:02d}" not in manual_review_ids
    }

    assert {
        item.weakness_id
        for item in KISA_CATALOG
        if item.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED
    } == partially_implemented_ids
    assert {
        item.weakness_id
        for item in KISA_CATALOG
        if item.implementation_status is ImplementationStatus.MANUAL_REVIEW_REQUIRED
    } == manual_review_ids
    assert not any(
        item.implementation_status is ImplementationStatus.IMPLEMENTED for item in KISA_CATALOG
    )
    assert not any(
        item.implementation_status is ImplementationStatus.NOT_IMPLEMENTED for item in KISA_CATALOG
    )


def test_catalog_preserves_kisa_source_footnotes_in_descriptions() -> None:
    format_string = KISA_CATALOG[16]
    salted_hash = KISA_CATALOG[30]
    deserialization = KISA_CATALOG[42]

    assert "* 포맷 스트링:" in format_string.description
    assert "* 솔트:" in salted_hash.description
    assert "* 직렬화:" in deserialization.description
    assert "* 역직렬화:" in deserialization.description


def test_catalog_preserves_kisa_source_name_spacing() -> None:
    assert KISA_CATALOG[17].name == "적절한 인증 없는 중요 기능 허용"
    assert KISA_CATALOG[34].name == "종료되지 않는 반복문 또는 재귀함수"
    assert KISA_CATALOG[45].name == "Public 메서드부터 반환된 Private 배열"
