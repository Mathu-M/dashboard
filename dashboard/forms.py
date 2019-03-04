"""
Web forms used in the flask app are defined here
Forms are defined using the WTForms api (https://wtforms.readthedocs.io/en/latest/)
    via Flask-WTForms extension.
This allows us to create HTML forms in python without having to worry about
    the html code.
"""

from flask import session
from flask_wtf import FlaskForm
from wtforms import SelectField, SelectMultipleField, HiddenField, SubmitField, \
        TextAreaField, TextField, FormField, BooleanField, widgets, FieldList, \
        RadioField
from wtforms.fields.html5 import EmailField, TelField
from wtforms.compat import iteritems
from wtforms.validators import DataRequired, Email
from models import Study, Analysis
from wtforms.csrf.session import SessionCSRF


from models import User, Site
from wtforms import StringField
from wtforms.validators import InputRequired, NoneOf, Length, Optional
from wtforms.widgets import html_params, HTMLString

class SelectMetricsForm(FlaskForm):
    study_vals = []
    site_vals = []
    session_vals = []
    scan_vals = []
    scantype_vals = []
    metrictype_vals = []

    study_id = SelectMultipleField('Study', coerce=int)
    site_id = SelectMultipleField('Site', coerce=int)
    session_id = SelectMultipleField('Session', coerce=int)
    scan_id = SelectMultipleField('Scan', coerce=int)
    scantype_id = SelectMultipleField('Scan type', coerce=int)
    metrictype_id = SelectMultipleField('Metric type', coerce=int)
    query_complete = HiddenField(default=False)
    is_phantom = HiddenField(default=False)

    def __init__(self,  *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)


class StudyOverviewForm(FlaskForm):
    readme_txt = TextAreaField(u'README', id='readme_editor')
    study_id = HiddenField()


class ScanChecklistForm(FlaskForm):
    comment = TextAreaField('Comment:', id='scan-comment',
            validators=[DataRequired()],
            render_kw={'placeholder': 'Add description', 'rows': 12,
                    'required': True, 'maxlength': '1028'})
    submit = SubmitField('Submit')


class UserForm(FlaskForm):
    id = HiddenField()
    first_name = TextField(u'First Name: ', validators=[DataRequired()],
            render_kw={'required': True, 'maxlength': '64',
            'placeholder': 'Jane'})
    last_name = TextField(u'Last Name: ', validators=[DataRequired()],
            render_kw={'required': True, 'maxlength': '64', 'placeholder': 'Doe'})
    email = EmailField(u'Email: ', validators=[DataRequired()],
            render_kw={'required': True, 'maxlength': '256', 'placeholder': 'Enter email'})
    provider = RadioField('Account provider: ',
            validators=[DataRequired()],
            choices=[(u'github', 'GitHub')], default='github')
    account = TextField(u'Username: ', validators=[DataRequired()],
            render_kw={'required': True, 'maxlength': '64', 'placeholder':
            'Username used on account provider\'s site'})
    position = TextField(u'Position: ', render_kw={'maxlength': '64',
            'placeholder': 'Job title or position'})
    institution = TextField(u'Institution: ', render_kw={'maxlength': '128',
            'placeholder': 'Full name or acronym for institution'})
    phone = TelField(u'Phone Number: ', render_kw={'maxlength': '20',
            'placeholder': '555-555-5555'})
    ext = TextField(u'Extension: ', render_kw={'maxlength': '10',
            'placeholder': 'XXXXXXXXXX'})
    alt_phone = TelField(u'Alt. Phone Number: ', render_kw={'maxlength': '20',
            'placeholder': '555-555-5555'})
    alt_ext = TextField(u'Alt. Extension: ', render_kw={'maxlength': '10',
            'placeholder': 'XXXXXXXXXX'})
    submit = SubmitField(u'Save Changes')


class PermissionRadioField(RadioField):
    def __init__(self, *args, **kwargs):
        super(PermissionRadioField, self).__init__(**kwargs)
        self.choices = [(u'False', 'Disabled'), (u'True', 'Enabled')]
        self.default = u'False'


class StudyPermissionsForm(FlaskForm):
    study_id = HiddenField()
    user_id = HiddenField()
    is_admin = PermissionRadioField(label='Study Admin')
    primary_contact = PermissionRadioField('Primary Contact')
    kimel_contact = PermissionRadioField('Kimel Contact')
    study_RA = PermissionRadioField('Study RA')
    does_qc = PermissionRadioField('Does QC')
    revoke_access = SubmitField('Remove')


class UserAdminForm(UserForm):
    dashboard_admin = BooleanField(u'Dashboard Admin: ')
    is_active = BooleanField(u'Active Account: ')
    studies = FieldList(FormField(StudyPermissionsForm))
    add_access = SelectMultipleField('Currently disabled studies: ')
    update_access = SubmitField(label='Enable')
    revoke_all_access = SubmitField(label='Remove All')

    def process(self, formdata=None, obj=None, data=None, **kwargs):
        """
        This is identical to WTForm 2.1's implementation of 'process',
        but it must pass in the User.studies.values() when it's called with
        an object instead of just User.studies, since studies is a mapped
        collection
        """
        formdata = self.meta.wrap_formdata(self, formdata)

        if data is not None:
            # XXX we want to eventually process 'data' as a new entity.
            #     Temporarily, this can simply be merged with kwargs.
            kwargs = dict(data, **kwargs)

        for name, field, in iteritems(self._fields):
            if obj is not None and hasattr(obj, name):
                ## This if statement is the only change made to the original
                ## code for BaseForm.process() - Dawn
                if name == 'studies':
                    field.process(formdata, obj.studies.values())
                else:
                    field.process(formdata, getattr(obj, name))
            elif name in kwargs:
                field.process(formdata, kwargs[name])
            else:
                field.process(formdata)

    def populate_obj(self, obj):
        """
        As with process, this implementation is the same as WTForm 2.1's
        default with the 'studies' field treated as a special case to
        account for the fact that it is a mapped collection
        """
        for name, field in iteritems(self._fields):
            if name == 'studies':
                for study_form in self.studies.entries:
                    study_form.form.populate_obj(
                            obj.studies[study_form.study_id.data])
            else:
                field.populate_obj(obj, name)


class AccessRequestForm(UserForm):
    studies = FieldList(FormField(StudyPermissionsForm))
    request_access = SelectMultipleField('Request access to studies: ')
    send_request = SubmitField(label='Submit Request')


class AnalysisForm(FlaskForm):
    name = TextField(u'Brief name',
                     validators=[DataRequired()])
    description = TextAreaField(u'Description',
                            validators=[DataRequired()])
    software = TextAreaField(u'Software')


class EmptySessionForm(FlaskForm):
    comment = TextAreaField(u'Explanation: ', id="missing_comment",
            validators=[DataRequired()],
            render_kw={'rows': 4, 'cols': 50, 'required': True,
                    'placeholder': 'Please describe what happened to this session.',
                    'maxlength': '2048'})


class IncidentalFindingsForm(FlaskForm):
    comment = TextAreaField(u'Description: ', id='finding-description',
            validators=[DataRequired()], render_kw={'rows': 4, 'cols': 65,
                    'required': True, 'placeholder': 'Please describe the finding'})
    submit = SubmitField('Submit')


class TimepointCommentsForm(FlaskForm):
    comment = TextAreaField(validators=[DataRequired()],
            render_kw={'rows': 5, 'required': True,
                    'placeholder': 'Add new comment'})
    submit = SubmitField('Submit')


class NewIssueForm(FlaskForm):
    title = TextField(u"Title: ", validators=[DataRequired()],
            render_kw={'required': True})
    body = TextAreaField(u"Body: ", validators=[DataRequired()],
            render_kw={'rows': 4, 'cols': 65, 'required': True,
            'placeholder': 'Enter issue here.'})
    submit = SubmitField('Create Issue')

def multi_checkbox_table(field, cols=1, **kwargs):
    html = []
    kwargs.setdefault('type', 'checkbox')
    field_id = kwargs.pop('id', field.id)
    html.append(u'<table %s class="table">' % html_params(**kwargs))
    i = 0
    for value, label, checked in sorted(field.iter_choices(), key=lambda (v,l,c): l):
        r = i % cols
        if r == 0:
            html.append('<tr>')
        choice_id = u'{}-{}'.format(field_id, value)
        options = dict(kwargs, name=field.name, value=value, id=choice_id)
        if checked:
            options['checked'] = 'checked'
        html.append(u'<td><input %s /> ' % html_params(**options))
        html.append(u'<label for="%s">%s</label></td>' % (field_id, label))
        if cols == 1 or r == (cols-1):
            html.append('</tr>')
        i= i + 1
    html.append('</table>')
    return HTMLString(''.join(html))

class StudyForm(FlaskForm):
    study_nickname = StringField(u'ID',
        render_kw={
            'size':30
        },
        validators=[
            NoneOf([], message=u'Study ID already exists'),
            InputRequired(u'Required Field'),
            Length(max=32, message=u'Length must be less than 33')
        ])
    study_name = StringField(u'Name',
        render_kw={
            'size':30
        },
        validators=[
            InputRequired(u'Required Field'),
            Length(max=1024, message=u'Length must be less than 1025')
        ])
    study_description = TextAreaField(u'Description',
        render_kw={
            'rows':3,
            'cols':40
        },
        validators=[
            Optional()
        ])
    study_readme = TextAreaField(u'README',
        render_kw={
            'rows':3,
            'cols':40
        },
        validators=[
            Optional()
        ])

    study_users = SelectMultipleField(u'Users',
        widget=multi_checkbox_table,
        render_kw={
            'cols':7
        },
        validators=[
            InputRequired(u'At least one User required')
        ])
    study_sites = SelectMultipleField(u'Sites',
        widget=multi_checkbox_table,
        render_kw={
            'cols':17
        },
        validators=[
            InputRequired(u'At least one Site required')
        ])

    submit_study = SubmitField(u'Add Study')


    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)

        studies = Study.query.all()
        study_nicknames = [str(study.id) for study in studies]
        self.study_nickname.validators[0].values = study_nicknames

        users = User.query.all()
        user_choices = [(str(user.id), " ".join([user.first_name, user.last_name])) for user in users]
        self.study_users.choices = user_choices

        sites = Site.query.all()
        site_choices = [(site.name, site.name) for site in sites]
        self.study_sites.choices = site_choices
