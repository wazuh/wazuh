#!/usr/bin/env python3
from health_test.test_suite import UnitResultInterface, UnitOutput, run as suite_run
from health_test.utils import *
import json


class UnitResult(UnitResultInterface):
    def __init__(self, index: int, expected: dict, actual: UnitOutput, target: str, help: str):
        self.index = index
        self.expected = expected
        self.help_file_path = help
        if not actual.success:
            self.error = actual.error
            self.success = False
        else:
            self.setup(actual.output)

    def setup(self, actual: dict):
        self.diff = {}
        filtered_expected = filter_nested(self.expected)
        filtered_actual = filter_nested(actual)

        if filtered_expected == filtered_actual:
            self.success = True
            return
        else:
            self.success = False
            self.update_expected_file(self.index, actual)

        # for key in filtered_expected:
        #     if key not in filtered_actual:
        #         self.diff[key] = {"info": "Missing key in actual result",
        #                           "expected": filtered_expected[key]}
        #         return
        #     elif filtered_expected[key] != filtered_actual[key]:
        #         self.diff[key] = {"info": "Mismatched value",
        #                           "expected": filtered_expected[key], "actual": filtered_actual[key]}
        # for key in filtered_actual:
        #     if key not in filtered_expected:
        #         self.diff[key] = {"info": "Extra key in actual result",
        #                           "actual": filtered_actual[key]}

    def update_expected_file(self, index: int, actual: dict):
        """
        Actualiza el archivo JSON en el índice dado con el contenido de `actual`.

        Args:
            index (int): Índice del elemento a reemplazar.
            actual (dict): Nuevo valor para reemplazar en el archivo.
        """
        try:
            # Leer el archivo JSON existente.
            with open(self.help_file_path, 'r') as file:
                data = json.load(file)

            # Asegurarse de que el archivo contiene un array de diccionarios.
            if not isinstance(data, list):
                raise ValueError("El archivo JSON debe contener una lista de diccionarios.")

            # Actualizar el índice correspondiente en el array.
            data[index] = actual

            # Sobrescribir el archivo JSON con los cambios.
            with open(self.help_file_path, 'w') as file:
                json.dump(data, file, indent=2)
                file.write('\n')

            # Actualizar el atributo `expected` en memoria.
            self.expected = data

        except (FileNotFoundError, ValueError, IndexError) as e:
            # Manejar errores relacionados con el archivo.
            self.error = f"Error actualizando el archivo JSON: {str(e)}"
            self.success = False


def run(args):
    return suite_run(args, UnitResult, debug_mode="")
