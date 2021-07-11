#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "kuro.h"
#include "structmember.h"

PyDoc_STRVAR(
  cryptbystringdoc,
  "cryptbystringdoc(/ input, mask, mask_len)\n"
  "--\n\n"
  "Return ``input`` as a decrypted ``bytes`` object.\n"
  "\n"
  "Parameters\n"
  "----------\n"
  "``input`` : ``bytes``\n"
  "``mask`` : ``bytes``\n"
  "  A UTF-16-LE encoded ``str`` to be used as a mask.\n"
  "``mask_len`` : ``str``\n"
  "  The length of the mask string before encoding.\n"
  "Returns\n"
  "-------\n"
  "``crypted_output`` : ``bytes``\n");

static PyObject *
method_CryptByString(PyObject * self, PyObject* args, PyObject* kwargs)
{
  static char* keywords[] = {"input", "mask", "mask_len", NULL };

  uint8_t* input = NULL;
  uint8_t* output = NULL;
  uint8_t* mask = NULL;
  Py_ssize_t input_len = 0;
  Py_ssize_t mask_len = 0;
  Py_ssize_t mask_s_len = 0;
  PyObject* py_output = NULL;
// TODO: I don't know how I managed this but for some reason if I try to get the length of the bytes using the bytes object itself
// the module causes a segfault, but if I pass length in seperately it doesnt????
  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "$y#y#n", keywords, &input, &input_len, &mask, &mask_len, &mask_s_len)) {
    return NULL;
  }
  CryptByString(input, input_len, &output, mask, (uint8_t)mask_s_len, 0, 0, 256);
  py_output = PyBytes_FromStringAndSize(output, input_len);
  free(output);
  return py_output;
}

static PyMethodDef
kuro_methods[] = {
  {"cryptbystring", (PyCFunction) method_CryptByString, METH_VARARGS | METH_KEYWORDS, cryptbystringdoc},
  {NULL}
};

static PyModuleDef
kuromodule = {
  PyModuleDef_HEAD_INIT,
  .m_name = "kuro",
  .m_doc = "Python interface for dark encryption used by NieR Rein.",
  .m_size = -1,
  .m_methods = kuro_methods
};

PyMODINIT_FUNC
PyInit_kuro(void)
{
  PyObject *m;
  m = PyModule_Create(&kuromodule);
  if (m == NULL)
    return NULL;
  return m;
}
