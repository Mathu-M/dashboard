#!/usr/bin/env python
"""
Helper functions for the routes defined in views.py to make them a bit more
readable :)
"""
import logging

from flask import flash, url_for
from werkzeug.routing import RequestRedirect

from .models import Study, Timepoint, Scan, RedcapRecord, User
from .forms import UserForm, UserAdminForm
from .utils import create_issue as make_issue

logger = logging.getLogger(__name__)

def get_user_form(user, current_user):
    if not current_user.dashboard_admin:
        form = UserForm(obj=user)
        form.account.data = user.username
        return form
    form = get_admin_user_form(user)
    return form

def get_admin_user_form(user):
    form = UserAdminForm(obj=user)
    form.account.data = user.username
    disabled_studies = user.get_disabled_studies()
    form.add_access.choices = [(study.id, study.id) for study in
            disabled_studies]
    return form

def report_form_errors(form):
    for field_name, errors in form.errors.items():
        try:
            label = getattr(form, field_name).label.text
        except:
            logger.error("Form {} reported an error for a field, but "
                "field was not found. field_name: {} error(s): {}".format(
                form, field_name, errors))
            continue
        for error in errors:
            flash('ERROR - {} {}'.format(label, error))

def handle_issue(token, issue_form, study_id, timepoint):
    title = clean_issue_title(issue_form.title.data, timepoint)
    study = Study.query.get(study_id)

    staff_member = study.choose_staff_contact()
    if staff_member:
        assigned_user = staff_member.username
    else:
        assigned_user = None

    try:
        issue = make_issue(token, title, issue_form.body.data,
                assign=assigned_user)
    except Exception as e:
        logger.error("Failed to create a GitHub issue for {}. "
                "Reason: {}".format(timepoint, e))
        flash("Failed to create issue '{}'".format(title))
    else:
        flash("Issue '{}' created!".format(title))

def clean_issue_title(title, timepoint):
    title = title.rstrip()
    if not title:
        title = timepoint
    elif title.endswith('-'):
        title = title[:-1].rstrip()
    elif timepoint not in title:
        title = timepoint + " - " + title
    return title

def get_timepoint(study_id, timepoint_id, current_user):
    timepoint = Timepoint.query.get(timepoint_id)

    if timepoint is None:
        flash("Timepoint {} does not exist".format(timepoint_id))
        raise RequestRedirect("index")

    if (not current_user.has_study_access(study_id) or
            not timepoint.belongs_to(study_id)):
        flash("Not authorised to view {}".format(timepoint_id))
        raise RequestRedirect("index")

    return timepoint

def get_session(timepoint, session_num, fail_url):
    try:
        session = timepoint.sessions[session_num]
    except KeyError:
        flash("Session {} does not exist for {}.".format(session_num, timepoint))
        raise RequestRedirect(fail_url)
    return session

def get_scan(scan_id, study_id, current_user, fail_url=None):
    if not fail_url:
        fail_url = url_for('index')

    scan = Scan.query.get(scan_id)

    if scan is None:
        logger.error("User {} attempted to retrieve scan with ID {}. Retrieval "
                "failed.".format(current_user, scan_id))
        flash("Scan does not exist.".format(scan_id))
        raise RequestRedirect(fail_url)

    if (not current_user.has_study_access(study_id) or
            not scan.session.timepoint.belongs_to(study_id)):
        flash("Not authorized to view {}".format(scan.name))
        raise RequestRedirect(fail_url)

    return scan

def get_redcap_record(record_id, fail_url=None):
    if not fail_url:
        fail_url = url_for('index')

    record = RedcapRecord.query.get(record_id)

    if record is None:
        logger.error("Tried and failed to retrieve RedcapRecord with "
                "ID {}".format(record_id))
        flash("Record not found.")
        raise RequestRedirect(fail_url)

    return record
