"""
The MIT License (MIT)

Copyright (c) 2015-2021 Rapptz
Copyright (c) 2021-present Disnake Development

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""

from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

from ..components import AnySelectMenu, SelectOption, StringSelectMenu
from ..enums import ComponentType
from ..partial_emoji import PartialEmoji
from ..utils import MISSING
from .item import DecoratedItem, Item

__all__ = (
    "BaseSelect",
    "StringSelect",
    "Select",
    "string_select",
    "select",
)

if TYPE_CHECKING:
    from typing_extensions import Self

    from ..emoji import Emoji
    from ..interactions import MessageInteraction
    from .item import ItemCallbackType
    from .view import View

V = TypeVar("V", bound="Optional[View]", covariant=True)
SelectMenuT = TypeVar("SelectMenuT", bound=AnySelectMenu)
SelectValueT = TypeVar("SelectValueT")


def _parse_select_options(
    options: Union[List[SelectOption], List[str], Dict[str, str]]
) -> List[SelectOption]:

    if isinstance(options, dict):
        return [SelectOption(label=key, value=val) for key, val in options.items()]

    return [opt if isinstance(opt, SelectOption) else SelectOption(label=opt) for opt in options]


class BaseSelect(Generic[SelectMenuT, SelectValueT, V], Item[V], ABC):
    """Represents an abstract UI select menu.

    This is usually represented as a drop down menu.

    This isn't meant to be used directly, instead use one of the concrete select menu types:

    - :class:`disnake.ui.StringSelect`

    .. versionadded:: 2.6
    """

    __repr_attributes__: Tuple[str, ...] = (
        "placeholder",
        "min_values",
        "max_values",
        "options",
        "disabled",
    )
    # We have to set this to MISSING in order to overwrite the abstract property from WrappedComponent
    _underlying: SelectMenuT = MISSING

    def __init__(
        self,
        underlying_type: Type[SelectMenuT],
        component_type: ComponentType,
        *,
        custom_id: str,
        placeholder: Optional[str],
        min_values: int,
        max_values: int,
        disabled: bool,
        row: Optional[int],
    ) -> None:
        super().__init__()
        self._selected_values: List[SelectValueT] = []
        self._provided_custom_id = custom_id is not MISSING
        custom_id = os.urandom(16).hex() if custom_id is MISSING else custom_id
        self._underlying = underlying_type._raw_construct(
            type=component_type,
            custom_id=custom_id,
            placeholder=placeholder,
            min_values=min_values,
            max_values=max_values,
            disabled=disabled,
        )
        self.row = row

    @property
    def custom_id(self) -> str:
        """:class:`str`: The ID of the select menu that gets received during an interaction."""
        return self._underlying.custom_id

    @custom_id.setter
    def custom_id(self, value: str):
        if not isinstance(value, str):
            raise TypeError("custom_id must be None or str")

        self._underlying.custom_id = value

    @property
    def placeholder(self) -> Optional[str]:
        """Optional[:class:`str`]: The placeholder text that is shown if nothing is selected, if any."""
        return self._underlying.placeholder

    @placeholder.setter
    def placeholder(self, value: Optional[str]):
        if value is not None and not isinstance(value, str):
            raise TypeError("placeholder must be None or str")

        self._underlying.placeholder = value

    @property
    def min_values(self) -> int:
        """:class:`int`: The minimum number of items that must be chosen for this select menu."""
        return self._underlying.min_values

    @min_values.setter
    def min_values(self, value: int):
        self._underlying.min_values = int(value)

    @property
    def max_values(self) -> int:
        """:class:`int`: The maximum number of items that must be chosen for this select menu."""
        return self._underlying.max_values

    @max_values.setter
    def max_values(self, value: int):
        self._underlying.max_values = int(value)

    @property
    def disabled(self) -> bool:
        """:class:`bool`: Whether the select menu is disabled."""
        return self._underlying.disabled

    @disabled.setter
    def disabled(self, value: bool):
        self._underlying.disabled = bool(value)

    @property
    def values(self) -> List[SelectValueT]:
        return self._selected_values

    @property
    def width(self) -> int:
        return 5

    def refresh_component(self, component: SelectMenuT) -> None:
        self._underlying = component

    def refresh_state(self, interaction: MessageInteraction) -> None:
        # TODO: change typing of `interaction.values`
        self._selected_values = interaction.values  # type: ignore

    @classmethod
    @abstractmethod
    def from_component(cls, component: SelectMenuT) -> Self:
        raise NotImplementedError

    def is_dispatchable(self) -> bool:
        """Whether the select menu is dispatchable. This will always return ``True``.

        :return type: :class:`bool`
        """
        return True


class StringSelect(BaseSelect[StringSelectMenu, str, V]):
    """Represents a UI string select menu.

    In order to get the items that the user has selected, use :attr:`values`.

    .. versionadded:: 2.0

    Parameters
    ----------
    custom_id: :class:`str`
        The ID of the select menu that gets received during an interaction.
        If not given then one is generated for you.
    placeholder: Optional[:class:`str`]
        The placeholder text that is shown if nothing is selected, if any.
    min_values: :class:`int`
        The minimum number of items that must be chosen for this select menu.
        Defaults to 1 and must be between 1 and 25.
    max_values: :class:`int`
        The maximum number of items that must be chosen for this select menu.
        Defaults to 1 and must be between 1 and 25.
    options: Union[List[:class:`disnake.SelectOption`], List[:class:`str`], Dict[:class:`str`, :class:`str`]]
        A list of options that can be selected in this menu. Use explicit :class:`.SelectOption`\\s
        for fine-grained control over the options. Alternatively, a list of strings will be treated
        as a list of labels, and a dict will be treated as a mapping of labels to values.

        .. versionchanged:: 2.5
            Now also accepts a list of str or a dict of str to str, which are then appropriately parsed as
            :class:`.SelectOption` labels and values.

    disabled: :class:`bool`
        Whether the select is disabled.
    row: Optional[:class:`int`]
        The relative row this select menu belongs to. A Discord component can only have 5
        rows. By default, items are arranged automatically into those 5 rows. If you'd
        like to control the relative positioning of the row then passing an index is advised.
        For example, row=1 will show up before row=2. Defaults to ``None``, which is automatic
        ordering. The row number must be between 0 and 4 (i.e. zero indexed).

    Attributes
    ----------
    values: List[:class:`str`]
        A list of values that have been selected by the user.
    """

    __repr_attributes__: Tuple[str, ...] = BaseSelect.__repr_attributes__ + ("options",)

    @overload
    def __init__(
        self: StringSelect[None],
        *,
        custom_id: str = MISSING,
        placeholder: Optional[str] = None,
        min_values: int = 1,
        max_values: int = 1,
        options: Union[List[SelectOption], List[str], Dict[str, str]] = MISSING,
        disabled: bool = False,
        row: Optional[int] = None,
    ):
        ...

    @overload
    def __init__(
        self: StringSelect[V],
        *,
        custom_id: str = MISSING,
        placeholder: Optional[str] = None,
        min_values: int = 1,
        max_values: int = 1,
        options: Union[List[SelectOption], List[str], Dict[str, str]] = MISSING,
        disabled: bool = False,
        row: Optional[int] = None,
    ):
        ...

    def __init__(
        self,
        *,
        custom_id: str = MISSING,
        placeholder: Optional[str] = None,
        min_values: int = 1,
        max_values: int = 1,
        options: Union[List[SelectOption], List[str], Dict[str, str]] = MISSING,
        disabled: bool = False,
        row: Optional[int] = None,
    ) -> None:
        super().__init__(
            StringSelectMenu,
            ComponentType.string_select,
            custom_id=custom_id,
            placeholder=placeholder,
            min_values=min_values,
            max_values=max_values,
            disabled=disabled,
            row=row,
        )
        self._underlying.options = [] if options is MISSING else _parse_select_options(options)

    @classmethod
    def from_component(cls, component: StringSelectMenu) -> Self:
        return cls(
            custom_id=component.custom_id,
            placeholder=component.placeholder,
            min_values=component.min_values,
            max_values=component.max_values,
            options=component.options,
            disabled=component.disabled,
            row=None,
        )

    @property
    def options(self) -> List[SelectOption]:
        """List[:class:`disnake.SelectOption`]: A list of options that can be selected in this select menu."""
        return self._underlying.options

    @options.setter
    def options(self, value: List[SelectOption]):
        if not isinstance(value, list):
            raise TypeError("options must be a list of SelectOption")
        if not all(isinstance(obj, SelectOption) for obj in value):
            raise TypeError("all list items must subclass SelectOption")

        self._underlying.options = value

    def add_option(
        self,
        *,
        label: str,
        value: str = MISSING,
        description: Optional[str] = None,
        emoji: Optional[Union[str, Emoji, PartialEmoji]] = None,
        default: bool = False,
    ):
        """Adds an option to the select menu.

        To append a pre-existing :class:`.SelectOption` use the
        :meth:`append_option` method instead.

        Parameters
        ----------
        label: :class:`str`
            The label of the option. This is displayed to users.
            Can only be up to 100 characters.
        value: :class:`str`
            The value of the option. This is not displayed to users.
            If not given, defaults to the label. Can only be up to 100 characters.
        description: Optional[:class:`str`]
            An additional description of the option, if any.
            Can only be up to 100 characters.
        emoji: Optional[Union[:class:`str`, :class:`.Emoji`, :class:`.PartialEmoji`]]
            The emoji of the option, if available. This can either be a string representing
            the custom or unicode emoji or an instance of :class:`.PartialEmoji` or :class:`.Emoji`.
        default: :class:`bool`
            Whether this option is selected by default.

        Raises
        ------
        ValueError
            The number of options exceeds 25.
        """
        option = SelectOption(
            label=label,
            value=value,
            description=description,
            emoji=emoji,
            default=default,
        )

        self.append_option(option)

    def append_option(self, option: SelectOption):
        """Appends an option to the select menu.

        Parameters
        ----------
        option: :class:`disnake.SelectOption`
            The option to append to the select menu.

        Raises
        ------
        ValueError
            The number of options exceeds 25.
        """
        if len(self._underlying.options) >= 25:
            raise ValueError("maximum number of options already provided")

        self._underlying.options.append(option)


Select = StringSelect  # backwards compatibility


def string_select(
    *,
    placeholder: Optional[str] = None,
    custom_id: str = MISSING,
    min_values: int = 1,
    max_values: int = 1,
    options: Union[List[SelectOption], List[str], Dict[str, str]] = MISSING,
    disabled: bool = False,
    row: Optional[int] = None,
) -> Callable[[ItemCallbackType[StringSelect]], DecoratedItem[StringSelect]]:
    """A decorator that attaches a string select menu to a component.

    The function being decorated should have three parameters, ``self`` representing
    the :class:`disnake.ui.View`, the :class:`disnake.ui.StringSelect` that was
    interacted with, and the :class:`disnake.MessageInteraction`.

    In order to get the selected items that the user has chosen within the callback
    use :attr:`StringSelect.values`.

    Parameters
    ----------
    placeholder: Optional[:class:`str`]
        The placeholder text that is shown if nothing is selected, if any.
    custom_id: :class:`str`
        The ID of the select menu that gets received during an interaction.
        It is recommended not to set this parameter to prevent conflicts.
    row: Optional[:class:`int`]
        The relative row this select menu belongs to. A Discord component can only have 5
        rows. By default, items are arranged automatically into those 5 rows. If you'd
        like to control the relative positioning of the row then passing an index is advised.
        For example, row=1 will show up before row=2. Defaults to ``None``, which is automatic
        ordering. The row number must be between 0 and 4 (i.e. zero indexed).
    min_values: :class:`int`
        The minimum number of items that must be chosen for this select menu.
        Defaults to 1 and must be between 1 and 25.
    max_values: :class:`int`
        The maximum number of items that must be chosen for this select menu.
        Defaults to 1 and must be between 1 and 25.
    options: Union[List[:class:`disnake.SelectOption`], List[:class:`str`], Dict[:class:`str`, :class:`str`]]
        A list of options that can be selected in this menu. Use explicit :class:`.SelectOption`\\s
        for fine-grained control over the options. Alternatively, a list of strings will be treated
        as a list of labels, and a dict will be treated as a mapping of labels to values.

        .. versionchanged:: 2.5
            Now also accepts a list of str or a dict of str to str, which are then appropriately parsed as
            :class:`.SelectOption` labels and values.

    disabled: :class:`bool`
        Whether the select is disabled. Defaults to ``False``.
    """

    def decorator(func: ItemCallbackType[StringSelect]) -> DecoratedItem[StringSelect]:
        if not asyncio.iscoroutinefunction(func):
            raise TypeError("select function must be a coroutine function")

        func.__discord_ui_model_type__ = StringSelect
        func.__discord_ui_model_kwargs__ = {
            "placeholder": placeholder,
            "custom_id": custom_id,
            "row": row,
            "min_values": min_values,
            "max_values": max_values,
            "options": options,
            "disabled": disabled,
        }
        return func  # type: ignore

    return decorator


select = string_select  # backwards compatibility
