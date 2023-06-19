



import magic


def file_checker(file):
    # Check the MIME type of the file using python-magic
    mime = magic.Magic(mime=True)
    mimetype = mime.from_buffer(file.read())
    if mimetype != 'application/pdf':
        raise "File is not a PDF"
    