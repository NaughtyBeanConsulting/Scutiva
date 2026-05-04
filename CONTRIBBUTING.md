# Contributing

Thank you for contributing to Scutiva.

## Ground rules

- Be respectful and assume good intent.
- Keep pull requests focused and easy to review.
- Prefer root-cause fixes over cosmetic patches.
- Add or update tests when behavior changes.
- Update documentation when setup, configuration, or workflows change.

## Development workflow

1. Fork the repository and create a feature branch.
2. Set up the local environment using the instructions in `README.md`.
3. Make small, reviewable commits.
4. Run the project checks before opening a pull request.
5. Open a pull request with a clear summary, test notes, and screenshots for UI changes.

## Python coding guidelines

- Follow standard Python style conventions.
- Use clear names instead of abbreviations.
- Keep functions short and cohesive.
- Prefer explicitness over cleverness.
- Use Django conventions for views, forms, models, and URL routing.
- Keep business logic out of templates.
- Keep settings environment-driven and avoid hard-coded secrets.

## Quality checks

Run these before submitting a pull request:

```bash
python manage.py check
python manage.py makemigrations --check
npm run build:css
```

## Pull request guidance

- Describe the problem being solved.
- Describe the technical approach.
- List any follow-up work that remains.
- Mention any database migrations or environment variable changes.

## Security

If you find a security issue, do not open a public issue with exploit details. Share the details privately with the maintainers first.