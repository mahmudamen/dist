# Copyright (C) 2010, 2011 Canonical Ltd
# Copyright (C) 2018 Breezy Developers
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

"""Support for Launchpad."""

from __future__ import absolute_import

import re

from .propose import (
    Hoster,
    LabelsUnsupported,
    MergeProposal,
    MergeProposalBuilder,
    MergeProposalExists,
    UnsupportedHoster,
    )

from ... import (
    branch as _mod_branch,
    controldir,
    errors,
    hooks,
    urlutils,
    )
from ...git.refs import ref_to_branch_name
from ...lazy_import import lazy_import
lazy_import(globals(), """
from breezy.plugins.launchpad import (
    lp_api,
    )

from launchpadlib import uris
""")
from ...transport import get_transport


# TODO(jelmer): Make selection of launchpad staging a configuration option.

def status_to_lp_mp_statuses(status):
    statuses = []
    if status in ('open', 'all'):
        statuses.extend([
            'Work in progress',
            'Needs review',
            'Approved',
            'Code failed to merge',
            'Queued'])
    if status in ('closed', 'all'):
        statuses.extend(['Rejected', 'Superseded'])
    if status in ('merged', 'all'):
        statuses.append('Merged')
    return statuses


def plausible_launchpad_url(url):
    if url is None:
        return False
    if url.startswith('lp:'):
        return True
    regex = re.compile(r'([a-z]*\+)*(bzr\+ssh|http|ssh|git|https)'
                       r'://(bazaar|git).*.launchpad.net')
    return bool(regex.match(url))


class WebserviceFailure(Exception):

    def __init__(self, message):
        self.message = message


def _call_webservice(call, *args, **kwargs):
    """Make a call to the webservice, wrapping failures.

    :param call: The call to make.
    :param *args: *args for the call.
    :param **kwargs: **kwargs for the call.
    :return: The result of calling call(*args, *kwargs).
    """
    from lazr.restfulclient import errors as restful_errors
    try:
        return call(*args, **kwargs)
    except restful_errors.HTTPError as e:
        error_lines = []
        for line in e.content.splitlines():
            if line.startswith(b'Traceback (most recent call last):'):
                break
            error_lines.append(line)
        raise WebserviceFailure(b''.join(error_lines))


class LaunchpadMergeProposal(MergeProposal):

    def __init__(self, mp):
        self._mp = mp

    def get_source_branch_url(self):
        if self._mp.source_branch:
            return self._mp.source_branch.bzr_identity
        else:
            branch_name = ref_to_branch_name(
                self._mp.source_git_path.encode('utf-8'))
            return urlutils.join_segment_parameters(
                self._mp.source_git_repository.git_identity,
                {"branch": branch_name})

    def get_target_branch_url(self):
        if self._mp.target_branch:
            return self._mp.target_branch.bzr_identity
        else:
            branch_name = ref_to_branch_name(
                self._mp.target_git_path.encode('utf-8'))
            return urlutils.join_segment_parameters(
                self._mp.target_git_repository.git_identity,
                {"branch": branch_name})

    @property
    def url(self):
        return lp_api.canonical_url(self._mp)

    def is_merged(self):
        return (self._mp.queue_status == 'Merged')

    def get_description(self):
        return self._mp.description

    def set_description(self, description):
        self._mp.description = description
        self._mp.lp_save()

    def close(self):
        self._mp.setStatus(status='Rejected')


class Launchpad(Hoster):
    """The Launchpad hosting service."""

    name = 'launchpad'

    # https://bugs.launchpad.net/launchpad/+bug/397676
    supports_merge_proposal_labels = False

    def __init__(self, staging=False):
        self._staging = staging
        if staging:
            lp_base_url = uris.STAGING_SERVICE_ROOT
        else:
            lp_base_url = uris.LPNET_SERVICE_ROOT
        self.launchpad = lp_api.connect_launchpad(lp_base_url)

    @property
    def base_url(self):
        return lp_api.uris.web_root_for_service_root(
            str(self.launchpad._root_uri))

    def __repr__(self):
        return "Launchpad(staging=%s)" % self._staging

    def hosts(self, branch):
        # TODO(jelmer): staging vs non-staging?
        return plausible_launchpad_url(branch.user_url)

    @classmethod
    def probe_from_url(cls, url):
        if plausible_launchpad_url(url):
            return Launchpad()
        raise UnsupportedHoster(url)

    def _get_lp_git_ref_from_branch(self, branch):
        url, params = urlutils.split_segment_parameters(branch.user_url)
        (scheme, user, password, host, port, path) = urlutils.parse_url(
            url)
        repo_lp = self.launchpad.git_repositories.getByPath(
            path=path.strip('/'))
        try:
            ref_path = params['ref']
        except KeyError:
            branch_name = params.get('branch', branch.name)
            if branch_name:
                ref_path = 'refs/heads/%s' % branch_name
            else:
                ref_path = repo_lp.default_branch
        ref_lp = repo_lp.getRefByPath(path=ref_path)
        return (repo_lp, ref_lp)

    def _get_lp_bzr_branch_from_branch(self, branch):
        return self.launchpad.branches.getByUrl(
            url=urlutils.unescape(branch.user_url))

    def _get_derived_git_path(self, base_path, owner, project):
        base_repo = self.launchpad.git_repositories.getByPath(path=base_path)
        if project is None:
            project = urlutils.parse_url(base_repo.git_ssh_url)[-1].strip('/')
        if project.startswith('~'):
            project = '/'.join(base_path.split('/')[1:])
        # TODO(jelmer): Surely there is a better way of creating one of these
        # URLs?
        return "~%s/%s" % (owner, project)

    def _publish_git(self, local_branch, base_path, name, owner, project=None,
                     revision_id=None, overwrite=False, allow_lossy=True):
        to_path = self._get_derived_git_path(base_path, owner, project)
        to_transport = get_transport("git+ssh://git.launchpad.net/" + to_path)
        try:
            dir_to = controldir.ControlDir.open_from_transport(to_transport)
        except errors.NotBranchError:
            # Didn't find anything
            dir_to = None

        if dir_to is None:
            try:
                br_to = local_branch.create_clone_on_transport(
                    to_transport, revision_id=revision_id, name=name)
            except errors.NoRoundtrippingSupport:
                br_to = local_branch.create_clone_on_transport(
                    to_transport, revision_id=revision_id, name=name,
                    lossy=True)
        else:
            try:
                dir_to = dir_to.push_branch(
                    local_branch, revision_id, overwrite=overwrite, name=name)
            except errors.NoRoundtrippingSupport:
                if not allow_lossy:
                    raise
                dir_to = dir_to.push_branch(
                    local_branch, revision_id, overwrite=overwrite, name=name,
                    lossy=True)
            br_to = dir_to.target_branch
        return br_to, (
            "https://git.launchpad.net/%s/+ref/%s" % (to_path, name))

    def _get_derived_bzr_path(self, base_branch, name, owner, project):
        if project is None:
            base_branch_lp = self._get_lp_bzr_branch_from_branch(base_branch)
            project = '/'.join(base_branch_lp.unique_name.split('/')[1:-1])
        # TODO(jelmer): Surely there is a better way of creating one of these
        # URLs?
        return "~%s/%s/%s" % (owner, project, name)

    def get_push_url(self, branch):
        (vcs, user, password, path, params) = self._split_url(branch.user_url)
        if vcs == 'bzr':
            branch_lp = self._get_lp_bzr_branch_from_branch(branch)
            return branch_lp.bzr_identity
        elif vcs == 'git':
            return urlutils.join_segment_parameters(
                "git+ssh://git.launchpad.net/" + path, params)
        else:
            raise AssertionError

    def _publish_bzr(self, local_branch, base_branch, name, owner,
                     project=None, revision_id=None, overwrite=False,
                     allow_lossy=True):
        to_path = self._get_derived_bzr_path(base_branch, name, owner, project)
        to_transport = get_transport("lp:" + to_path)
        try:
            dir_to = controldir.ControlDir.open_from_transport(to_transport)
        except errors.NotBranchError:
            # Didn't find anything
            dir_to = None

        if dir_to is None:
            br_to = local_branch.create_clone_on_transport(
                to_transport, revision_id=revision_id)
        else:
            br_to = dir_to.push_branch(
                local_branch, revision_id, overwrite=overwrite).target_branch
        return br_to, ("https://code.launchpad.net/" + to_path)

    def _split_url(self, url):
        url, params = urlutils.split_segment_parameters(url)
        (scheme, user, password, host, port, path) = urlutils.parse_url(url)
        path = path.strip('/')
        if host.startswith('bazaar.'):
            vcs = 'bzr'
        elif host.startswith('git.'):
            vcs = 'git'
        else:
            raise ValueError("unknown host %s" % host)
        return (vcs, user, password, path, params)

    def publish_derived(self, local_branch, base_branch, name, project=None,
                        owner=None, revision_id=None, overwrite=False,
                        allow_lossy=True):
        """Publish a branch to the site, derived from base_branch.

        :param base_branch: branch to derive the new branch from
        :param new_branch: branch to publish
        :param name: Name of the new branch on the remote host
        :param project: Optional project name
        :param owner: Optional owner
        :return: resulting branch
        """
        if owner is None:
            owner = self.launchpad.me.name
        (base_vcs, base_user, base_password, base_path,
            base_params) = self._split_url(base_branch.user_url)
        # TODO(jelmer): Prevent publishing to development focus
        if base_vcs == 'bzr':
            return self._publish_bzr(
                local_branch, base_branch, name, project=project, owner=owner,
                revision_id=revision_id, overwrite=overwrite,
                allow_lossy=allow_lossy)
        elif base_vcs == 'git':
            return self._publish_git(
                local_branch, base_path, name, project=project, owner=owner,
                revision_id=revision_id, overwrite=overwrite,
                allow_lossy=allow_lossy)
        else:
            raise AssertionError('not a valid Launchpad URL')

    def get_derived_branch(self, base_branch, name, project=None, owner=None):
        if owner is None:
            owner = self.launchpad.me.name
        (base_vcs, base_user, base_password, base_path,
            base_params) = self._split_url(base_branch.user_url)
        if base_vcs == 'bzr':
            to_path = self._get_derived_bzr_path(
                base_branch, name, owner, project)
            return _mod_branch.Branch.open("lp:" + to_path)
        elif base_vcs == 'git':
            to_path = self._get_derived_git_path(
                base_path.strip('/'), owner, project)
            to_url = urlutils.join_segment_parameters(
                "git+ssh://git.launchpad.net/" + to_path,
                {'branch': name})
            return _mod_branch.Branch.open(to_url)
        else:
            raise AssertionError('not a valid Launchpad URL')

    def iter_proposals(self, source_branch, target_branch, status='open'):
        (base_vcs, base_user, base_password, base_path,
            base_params) = self._split_url(target_branch.user_url)
        statuses = status_to_lp_mp_statuses(status)
        if base_vcs == 'bzr':
            target_branch_lp = self.launchpad.branches.getByUrl(
                url=target_branch.user_url)
            source_branch_lp = self.launchpad.branches.getByUrl(
                url=source_branch.user_url)
            for mp in target_branch_lp.getMergeProposals(status=statuses):
                if mp.source_branch_link != source_branch_lp.self_link:
                    continue
                yield LaunchpadMergeProposal(mp)
        elif base_vcs == 'git':
            (source_repo_lp, source_branch_lp) = (
                self._get_lp_git_ref_from_branch(source_branch))
            (target_repo_lp, target_branch_lp) = (
                self._get_lp_git_ref_from_branch(target_branch))
            for mp in target_branch_lp.getMergeProposals(status=statuses):
                if (target_branch_lp.path != mp.target_git_path or
                        target_repo_lp != mp.target_git_repository or
                        source_branch_lp.path != mp.source_git_path or
                        source_repo_lp != mp.source_git_repository):
                    continue
                yield LaunchpadMergeProposal(mp)
        else:
            raise AssertionError('not a valid Launchpad URL')

    def get_proposer(self, source_branch, target_branch):
        (base_vcs, base_user, base_password, base_path,
            base_params) = self._split_url(target_branch.user_url)
        if base_vcs == 'bzr':
            return LaunchpadBazaarMergeProposalBuilder(
                self, source_branch, target_branch)
        elif base_vcs == 'git':
            return LaunchpadGitMergeProposalBuilder(
                self, source_branch, target_branch)
        else:
            raise AssertionError('not a valid Launchpad URL')

    @classmethod
    def iter_instances(cls):
        yield cls()

    def iter_my_proposals(self, status='open'):
        statuses = status_to_lp_mp_statuses(status)
        for mp in self.launchpad.me.getMergeProposals(status=statuses):
            yield LaunchpadMergeProposal(mp)


class LaunchpadBazaarMergeProposalBuilder(MergeProposalBuilder):

    def __init__(self, lp_host, source_branch, target_branch, message=None,
                 staging=None, approve=None, fixes=None):
        """Constructor.

        :param source_branch: The branch to propose for merging.
        :param target_branch: The branch to merge into.
        :param message: The commit message to use.  (May be None.)
        :param staging: If True, propose the merge against staging instead of
            production.
        :param approve: If True, mark the new proposal as approved immediately.
            This is useful when a project permits some things to be approved
            by the submitter (e.g. merges between release and deployment
            branches).
        """
        self.lp_host = lp_host
        self.launchpad = lp_host.launchpad
        self.source_branch = source_branch
        self.source_branch_lp = self.launchpad.branches.getByUrl(
            url=source_branch.user_url)
        if target_branch is None:
            self.target_branch_lp = self.source_branch_lp.get_target()
            self.target_branch = _mod_branch.Branch.open(
                self.target_branch_lp.bzr_identity)
        else:
            self.target_branch = target_branch
            self.target_branch_lp = self.launchpad.branches.getByUrl(
                url=target_branch.user_url)
        self.commit_message = message
        self.approve = approve
        self.fixes = fixes

    def get_infotext(self):
        """Determine the initial comment for the merge proposal."""
        if self.commit_message is not None:
            return self.commit_message.strip().encode('utf-8')
        info = ["Source: %s\n" % self.source_branch_lp.bzr_identity]
        info.append("Target: %s\n" % self.target_branch_lp.bzr_identity)
        return ''.join(info)

    def get_initial_body(self):
        """Get a body for the proposal for the user to modify.

        :return: a str or None.
        """
        if not self.hooks['merge_proposal_body']:
            return None

        def list_modified_files():
            lca_tree = self.source_branch_lp.find_lca_tree(
                self.target_branch_lp)
            source_tree = self.source_branch.basis_tree()
            files = modified_files(lca_tree, source_tree)
            return list(files)
        with self.target_branch.lock_read(), \
                self.source_branch.lock_read():
            body = None
            for hook in self.hooks['merge_proposal_body']:
                body = hook({
                    'target_branch': self.target_branch_lp.bzr_identity,
                    'modified_files_callback': list_modified_files,
                    'old_body': body,
                })
            return body

    def check_proposal(self):
        """Check that the submission is sensible."""
        if self.source_branch_lp.self_link == self.target_branch_lp.self_link:
            raise errors.BzrCommandError(
                'Source and target branches must be different.')
        for mp in self.source_branch_lp.landing_targets:
            if mp.queue_status in ('Merged', 'Rejected'):
                continue
            if mp.target_branch.self_link == self.target_branch_lp.self_link:
                raise MergeProposalExists(lp_api.canonical_url(mp))

    def approve_proposal(self, mp):
        with self.source_branch.lock_read():
            _call_webservice(
                mp.createComment,
                vote=u'Approve',
                subject='',  # Use the default subject.
                content=u"Rubberstamp! Proposer approves of own proposal.")
            _call_webservice(mp.setStatus, status=u'Approved',
                             revid=self.source_branch.last_revision())

    def create_proposal(self, description, reviewers=None, labels=None,
                        prerequisite_branch=None):
        """Perform the submission."""
        if labels:
            raise LabelsUnsupported()
        if prerequisite_branch is not None:
            prereq = self.launchpad.branches.getByUrl(
                url=prerequisite_branch.user_url)
        else:
            prereq = None
        if reviewers is None:
            reviewers = []
        try:
            mp = _call_webservice(
                self.source_branch_lp.createMergeProposal,
                target_branch=self.target_branch_lp,
                prerequisite_branch=prereq,
                initial_comment=description.strip(),
                commit_message=self.commit_message,
                reviewers=[self.launchpad.people[reviewer].self_link
                           for reviewer in reviewers],
                review_types=[None for reviewer in reviewers])
        except WebserviceFailure as e:
            # Urgh.
            if (b'There is already a branch merge proposal '
                    b'registered for branch ') in e.message:
                raise MergeProposalExists(self.source_branch.user_url)
            raise

        if self.approve:
            self.approve_proposal(mp)
        if self.fixes:
            if self.fixes.startswith('lp:'):
                self.fixes = self.fixes[3:]
            _call_webservice(
                mp.linkBug,
                bug=self.launchpad.bugs[int(self.fixes)])
        return LaunchpadMergeProposal(mp)


class LaunchpadGitMergeProposalBuilder(MergeProposalBuilder):

    def __init__(self, lp_host, source_branch, target_branch, message=None,
                 staging=None, approve=None, fixes=None):
        """Constructor.

        :param source_branch: The branch to propose for merging.
        :param target_branch: The branch to merge into.
        :param message: The commit message to use.  (May be None.)
        :param staging: If True, propose the merge against staging instead of
            production.
        :param approve: If True, mark the new proposal as approved immediately.
            This is useful when a project permits some things to be approved
            by the submitter (e.g. merges between release and deployment
            branches).
        """
        self.lp_host = lp_host
        self.launchpad = lp_host.launchpad
        self.source_branch = source_branch
        (self.source_repo_lp,
            self.source_branch_lp) = self.lp_host._get_lp_git_ref_from_branch(
                source_branch)
        if target_branch is None:
            self.target_branch_lp = self.source_branch.get_target()
            self.target_branch = _mod_branch.Branch.open(
                self.target_branch_lp.git_https_url)
        else:
            self.target_branch = target_branch
            (self.target_repo_lp, self.target_branch_lp) = (
                self.lp_host._get_lp_git_ref_from_branch(target_branch))
        self.commit_message = message
        self.approve = approve
        self.fixes = fixes

    def get_infotext(self):
        """Determine the initial comment for the merge proposal."""
        if self.commit_message is not None:
            return self.commit_message.strip().encode('utf-8')
        info = ["Source: %s\n" % self.source_branch.user_url]
        info.append("Target: %s\n" % self.target_branch.user_url)
        return ''.join(info)

    def get_initial_body(self):
        """Get a body for the proposal for the user to modify.

        :return: a str or None.
        """
        if not self.hooks['merge_proposal_body']:
            return None

        def list_modified_files():
            lca_tree = self.source_branch_lp.find_lca_tree(
                self.target_branch_lp)
            source_tree = self.source_branch.basis_tree()
            files = modified_files(lca_tree, source_tree)
            return list(files)
        with self.target_branch.lock_read(), \
                self.source_branch.lock_read():
            body = None
            for hook in self.hooks['merge_proposal_body']:
                body = hook({
                    'target_branch': self.target_branch,
                    'modified_files_callback': list_modified_files,
                    'old_body': body,
                })
            return body

    def check_proposal(self):
        """Check that the submission is sensible."""
        if self.source_branch_lp.self_link == self.target_branch_lp.self_link:
            raise errors.BzrCommandError(
                'Source and target branches must be different.')
        for mp in self.source_branch_lp.landing_targets:
            if mp.queue_status in ('Merged', 'Rejected'):
                continue
            if mp.target_branch.self_link == self.target_branch_lp.self_link:
                raise MergeProposalExists(lp_api.canonical_url(mp))

    def approve_proposal(self, mp):
        with self.source_branch.lock_read():
            _call_webservice(
                mp.createComment,
                vote=u'Approve',
                subject='',  # Use the default subject.
                content=u"Rubberstamp! Proposer approves of own proposal.")
            _call_webservice(
                mp.setStatus, status=u'Approved',
                revid=self.source_branch.last_revision())

    def create_proposal(self, description, reviewers=None, labels=None,
                        prerequisite_branch=None):
        """Perform the submission."""
        if labels:
            raise LabelsUnsupported()
        if prerequisite_branch is not None:
            (prereq_repo_lp, prereq_branch_lp) = (
                self.lp_host._get_lp_git_ref_from_branch(prerequisite_branch))
        else:
            prereq_branch_lp = None
        if reviewers is None:
            reviewers = []
        try:
            mp = _call_webservice(
                self.source_branch_lp.createMergeProposal,
                merge_target=self.target_branch_lp,
                merge_prerequisite=prereq_branch_lp,
                initial_comment=description.strip(),
                commit_message=self.commit_message,
                needs_review=True,
                reviewers=[self.launchpad.people[reviewer].self_link
                           for reviewer in reviewers],
                review_types=[None for reviewer in reviewers])
        except WebserviceFailure as e:
            # Urgh.
            if ('There is already a branch merge proposal '
                    'registered for branch ') in e.message:
                raise MergeProposalExists(self.source_branch.user_url)
            raise
        if self.approve:
            self.approve_proposal(mp)
        if self.fixes:
            if self.fixes.startswith('lp:'):
                self.fixes = self.fixes[3:]
            _call_webservice(
                mp.linkBug,
                bug=self.launchpad.bugs[int(self.fixes)])
        return LaunchpadMergeProposal(mp)


def modified_files(old_tree, new_tree):
    """Return a list of paths in the new tree with modified contents."""
    for f, (op, path), c, v, p, n, (ok, k), e in new_tree.iter_changes(
            old_tree):
        if c and k == 'file':
            yield str(path)
