"""Language-aware content coverage: only English and Hebrew content is covered; other languages and empty
bodies reduce coverage so content analysis alone can never support a benign verdict."""
import pytest

from app.content_analysis import run_content_analysis
from app.content_analysis.text_utils import (
    NONE_COVERAGE,
    SUPPORTED_COVERAGE,
    UNDETERMINED_COVERAGE,
    UNSUPPORTED_COVERAGE,
    detect_language,
)
from app.contracts.findings import ModuleResult
from app.parser import parse_email_file
from app.scoring import run_scoring
from app.scoring.aggregate import category_coverage

TEXTS = {
    "english": "Please review the attached document and let us know if you have any questions about this request for the team. We kindly ask for a reply by the end of the week so that the matter can be closed.",
    "german": "Bitte prüfen Sie das beigefügte Dokument und teilen Sie uns mit, ob Sie Fragen zu dieser Anfrage für das Team haben. Wir bitten um eine Antwort bis zum Ende der Woche, damit der Vorgang abgeschlossen werden kann.",
    "french": "Veuillez consulter le document ci-joint et nous indiquer si vous avez des questions sur cette demande pour notre équipe. Nous vous prions de répondre avant la fin de la semaine afin que le dossier puisse être clos.",
    "spanish": "Por favor revise el documento adjunto y háganos saber si tiene alguna pregunta sobre esta solicitud para nuestro equipo. Le pedimos que responda antes del final de la semana para que el proceso pueda cerrarse.",
    "portuguese": "Por favor, reveja o documento em anexo e diga-nos se tem alguma dúvida sobre este pedido para a nossa equipa. Pedimos que responda antes do fim da semana para que o processo possa ser encerrado.",
    "italian": "Si prega di controllare il documento allegato e di farci sapere se ha domande su questa richiesta per il nostro team. Le chiediamo di rispondere entro la fine della settimana in modo che la pratica possa essere chiusa.",
    "dutch": "Bekijk het bijgevoegde document en laat ons weten als u vragen heeft over deze aanvraag voor ons team. Wij verzoeken u om voor het einde van de week te reageren zodat het dossier kan worden gesloten.",
    "polish": "Prosimy o zapoznanie się z załączonym dokumentem i poinformowanie nas, czy mają Państwo pytania dotyczące tej prośby dla naszego zespołu. Prosimy o odpowiedź do końca tygodnia, aby sprawa mogła zostać zamknięta.",
    "swedish": "Vänligen granska det bifogade dokumentet och låt oss veta om du har några frågor om denna begäran för vårt team. Vi ber om svar senast i slutet av veckan så att ärendet kan avslutas.",
}
HEBREW = "שלום רב, אנא עיינו במסמך המצורף ועדכנו אותנו אם יש לכם שאלות בנוגע לבקשה זו עבור הצוות שלנו לפני סוף השבוע."


# ---- the detector ----------------------------------------------------------------------------------

def test_english_and_hebrew_are_supported_with_full_coverage():
    for text, language in ((TEXTS["english"], "english"), (HEBREW, "hebrew")):
        info = detect_language(text)
        assert (info.status, info.language, info.coverage) == ("supported", language, SUPPORTED_COVERAGE)


@pytest.mark.parametrize("name", ["german", "french", "spanish", "portuguese", "italian", "dutch"])
def test_other_latin_script_languages_are_identified_and_unsupported(name):
    info = detect_language(TEXTS[name])
    assert (info.status, info.language, info.coverage) == ("unsupported", name, UNSUPPORTED_COVERAGE)


@pytest.mark.parametrize("name", ["polish", "swedish"])
def test_languages_without_any_list_are_still_recognised_as_not_english(name):
    info = detect_language(TEXTS[name])
    assert info.status == "unsupported" and info.coverage == UNSUPPORTED_COVERAGE


@pytest.mark.parametrize(
    "text,script",
    [("Пожалуйста, подтвердите свою учетную запись немедленно, иначе она будет заблокирована", "cyrillic"),
     ("يرجى تأكيد حسابك على الفور وإلا سيتم حظره قريبا جدا لأسباب أمنية", "arabic"),
     ("お客様のアカウントを今すぐ確認してください。そうしないとアカウントがブロックされます", "cjk")],
)
def test_other_scripts_are_unsupported_and_named(text, script):
    info = detect_language(text)
    assert (info.status, info.language, info.coverage) == ("unsupported", script, UNSUPPORTED_COVERAGE)


def test_short_but_decisive_english_is_supported_and_short_german_is_not():
    assert detect_language("Please see the attached invoice for your records and let me know if you have questions.").status == "supported"
    assert detect_language("Bitte sehen Sie die Rechnung im Anhang und melden Sie sich bei Fragen.").status == "unsupported"


def test_too_little_text_is_undetermined_not_full_coverage():
    for text in ("hi", "OK thanks", "123 456"):
        info = detect_language(text)
        assert info.status in ("undetermined", "none") and info.coverage < SUPPORTED_COVERAGE


def test_empty_text_has_no_readable_content():
    for text in ("", "   \n", "<https://t.example.org/a> <https://t.example.org/b>"):
        info = detect_language(text)
        assert (info.status, info.coverage) == ("none", NONE_COVERAGE)


def test_link_text_cannot_turn_hebrew_into_another_language_or_pad_a_short_message():
    links = " ".join(f"<https://tracking-host-{i}.example.org/some/long/path/{i}?token=abcdefghijkl>" for i in range(15))
    assert detect_language(HEBREW + " " + links).language == "hebrew"
    assert detect_language("ok " + links).status != "supported"


def test_mixed_hebrew_and_english_is_supported_either_way():
    assert detect_language(HEBREW + " " + TEXTS["english"]).status == "supported"


def test_coverage_values_are_ordered_supported_over_undetermined_over_unsupported():
    assert SUPPORTED_COVERAGE > UNDETERMINED_COVERAGE > UNSUPPORTED_COVERAGE == NONE_COVERAGE


# ---- through content analysis and scoring ---------------------------------------------------------------

def _eml(body, html=None):
    parts = ["From: S <s@sender.example.com>", "To: t@example.com", "Subject: s", "MIME-Version: 1.0"]
    if html is None:
        parts += ["Content-Type: text/plain; charset=utf-8", "", body]
    else:
        parts += ['Content-Type: multipart/alternative; boundary="B"', "", "--B", "Content-Type: text/plain; charset=utf-8", "", body,
                  "--B", "Content-Type: text/html; charset=utf-8", "", html, "--B--"]
    return "\r\n".join(parts).encode("utf-8")


def _analyze(raw):
    return run_content_analysis(parse_email_file(raw, "x.eml"))


def test_an_unsupported_language_is_visible_and_reduces_coverage_without_scoring():
    result = _analyze(_eml(TEXTS["german"]))
    finding = next(f for f in result.findings if f.title == "Content analysis does not cover this language")
    assert finding.severity == "info" and finding.weight == 0.0 and finding.evidence["language"] == "german"
    assert "can never support a 'No indicators found' verdict" in finding.description
    assert result.raw_data["script_coverage"] == UNSUPPORTED_COVERAGE and result.raw_data["language"]["status"] == "unsupported"
    assert category_coverage("content_analysis", result) == UNSUPPORTED_COVERAGE


def test_supported_language_has_no_language_finding_and_full_coverage():
    result = _analyze(_eml(TEXTS["english"]))
    assert not [f for f in result.findings if "language" in f.title.lower() or "readable text" in f.title.lower()]
    assert result.raw_data["script_coverage"] == SUPPORTED_COVERAGE


def test_an_image_only_message_says_there_is_nothing_to_read():
    result = _analyze(_eml("", html='<html><body><img src="https://img.example.org/a.png"></body></html>'))
    finding = next(f for f in result.findings if f.title == "No readable text for content analysis")
    assert finding.weight == 0.0 and "absence of evidence, not evidence of safety" in finding.description
    assert result.raw_data["script_coverage"] == NONE_COVERAGE


def test_the_urgency_lexicon_was_not_extended_to_other_languages():
    # scope is English/Hebrew by design: urgent German is NOT detected, and the finding says why
    result = _analyze(_eml("Bestätigen Sie Ihr Konto sofort, sonst wird Ihr Konto gesperrt. Dies ist die letzte Warnung für Ihr Konto und Ihre Daten hier."))
    assert not [f for f in result.findings if f.severity != "info" or f.weight > 0]
    assert any(f.title == "Content analysis does not cover this language" for f in result.findings)


def test_lower_content_coverage_lowers_overall_confidence():
    def confidence(content_cov):
        auth = ModuleResult(module="auth_check", status="ok", findings=[], raw_data={"auth_headers": {"header_present": True}})
        enrichment = ModuleResult(module="enrichment", status="ok", findings=[], raw_data={})
        content = ModuleResult(module="content_analysis", status="ok", findings=[], raw_data={"script_coverage": content_cov})
        return run_scoring([auth, enrichment, content]).confidence

    assert confidence(SUPPORTED_COVERAGE) > confidence(UNDETERMINED_COVERAGE) > confidence(UNSUPPORTED_COVERAGE)
