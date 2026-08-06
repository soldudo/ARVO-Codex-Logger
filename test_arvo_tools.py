import subprocess
from unittest.mock import patch

from arvo_tools import prune_dind_images, refuzz


def _completed(returncode=0, stdout='', stderr=''):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _rmi_tags(mock_run_command):
    """Image tags passed to `docker rmi` across all calls."""
    return [call.args[0][-1] for call in mock_run_command.call_args_list
            if 'rmi' in call.args[0]]


@patch('arvo_tools.run_command')
def test_refuzz(mock_run_command):
    mock_run_command.return_value = _completed(stdout='crash reproduced')

    result = refuzz('vulnscan')

    cmd = mock_run_command.call_args.args[0]
    assert cmd == ['docker', 'exec', 'vulnscan', 'arvo']
    assert result.stdout == 'crash reproduced'


@patch('arvo_tools.run_command')
def test_prune_keeps_current_vuln_and_removes_the_rest(mock_run_command):
    mock_run_command.side_effect = [
        _completed(stdout='n132/arvo:A-vul\nn132/arvo:B-vul\nn132/arvo:C-vul\n'),
        _completed(),  # rmi A
        _completed(),  # rmi C
    ]

    removed = prune_dind_images('B')

    assert _rmi_tags(mock_run_command) == ['n132/arvo:A-vul', 'n132/arvo:C-vul']
    assert removed == ['n132/arvo:A-vul', 'n132/arvo:C-vul']


@patch('arvo_tools.run_command')
def test_prune_keeps_both_flags_of_current_vuln(mock_run_command):
    mock_run_command.side_effect = [
        _completed(stdout='n132/arvo:B-vul\nn132/arvo:B-fix\nn132/arvo:A-fix\n'),
        _completed(),  # rmi A-fix
    ]

    prune_dind_images('B')

    assert _rmi_tags(mock_run_command) == ['n132/arvo:A-fix']


@patch('arvo_tools.run_command')
def test_prune_is_noop_on_resume_of_same_vuln(mock_run_command):
    mock_run_command.return_value = _completed(stdout='n132/arvo:B-vul\n')

    removed = prune_dind_images('B')

    assert _rmi_tags(mock_run_command) == []
    assert removed == []
    assert mock_run_command.call_count == 1  # listing only


@patch('arvo_tools.run_command')
def test_prune_is_noop_when_no_images_resident(mock_run_command):
    mock_run_command.return_value = _completed(stdout='')

    assert prune_dind_images('B') == []
    assert mock_run_command.call_count == 1


@patch('arvo_tools.run_command')
def test_prune_lists_from_the_named_rootainer(mock_run_command):
    mock_run_command.return_value = _completed(stdout='')

    prune_dind_images(42531212, rootainer_name='other-rootainer')

    assert mock_run_command.call_args.args[0] == [
        'docker', 'exec', 'other-rootainer',
        'docker', 'images', 'n132/arvo', '--format', '{{.Repository}}:{{.Tag}}',
    ]


@patch('arvo_tools.run_command')
def test_prune_tolerates_failing_rmi(mock_run_command):
    mock_run_command.side_effect = [
        _completed(stdout='n132/arvo:A-vul\nn132/arvo:C-vul\n'),
        _completed(returncode=1, stderr='image is being used by running container'),
        _completed(),  # rmi C still attempted
    ]

    removed = prune_dind_images('B')

    assert _rmi_tags(mock_run_command) == ['n132/arvo:A-vul', 'n132/arvo:C-vul']
    assert removed == ['n132/arvo:C-vul']


@patch('arvo_tools.run_command')
def test_prune_skips_when_listing_fails(mock_run_command):
    mock_run_command.return_value = _completed(returncode=1, stderr='no such container')

    assert prune_dind_images('B') == []
    assert _rmi_tags(mock_run_command) == []
