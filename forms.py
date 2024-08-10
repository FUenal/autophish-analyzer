## import modules
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired

## define UploadForm class inheriting from FlaskForm
class UploadForm(FlaskForm):
    # define a file field for uploading EML files with a validator to ensure the field is not empty
    eml_file = FileField('Upload EML File', validators=[DataRequired()])
    
    # define a submit button with the label 'Analyze'
    submit = SubmitField('Analyze')
