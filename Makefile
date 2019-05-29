build_lib:
	python3 setup.py sdist bdist_wheel

push_lib:
	python3 -m twine upload dist/* --skip-existing
