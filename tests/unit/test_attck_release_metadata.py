from argusprowl.attck.knowledge_service import AttckKnowledgeService


def test_collection_release_version_takes_precedence_over_matrix_object_version():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "18.1"},
            {"type": "x-mitre-matrix", "x_mitre_version": "1.0"},
        ],
    }

    assert AttckKnowledgeService._extract_version(bundle) == "18.1"


def test_matrix_version_is_fallback_for_older_bundles_without_collection():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-matrix", "x_mitre_version": "16.1"},
        ],
    }

    assert AttckKnowledgeService._extract_version(bundle) == "16.1"
